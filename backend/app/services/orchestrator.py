import logging
import threading
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Callable, Optional

import numpy as np

from app.config import (
    HOST_ID, WINDOW_SECONDS, FEATURE_NAMES,
    MIN_TRAINING_SAMPLES, RETRAIN_INTERVAL_HOURS,
)
from app.db.session import SessionLocal
from app.db.models import (
    RawEvent, FeatureWindow, Alert, Incident, HostBaseline,
)
from app.collectors.host_windows import WindowsHostCollector
from app.features.pipeline import compute_features, compute_context
from app.detection.model import AnomalyDetector
from app.correlation.engine import CorrelationEngine
from app.explanation.llm_explainer import OllamaExplainer
from app.explanation.templates import AlertExplainer
from app.mitre.mapper import MitreMapper
from app.threat_intel.enricher import ThreatIntelEnricher

logger = logging.getLogger(__name__)


class Orchestrator:
    """Polling-based pipeline loop: collect -> featurize -> detect -> correlate -> explain."""

    def __init__(self):
        self.collector = WindowsHostCollector(host_id=HOST_ID)
        self.detector = AnomalyDetector()
        self.correlator = CorrelationEngine()
        self.llm_explainer = OllamaExplainer()
        self.template_explainer = AlertExplainer()
        self.mitre_mapper = MitreMapper()
        self.threat_enricher = ThreatIntelEnricher()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_retrain_time = datetime.now(timezone.utc)
        self._broadcast_callbacks: List[Callable] = []

    def register_broadcast(self, callback: Callable):
        self._broadcast_callbacks.append(callback)

    def _broadcast(self, event_type: str, payload: Dict[str, Any]):
        for cb in self._broadcast_callbacks:
            try:
                cb(event_type, payload)
            except Exception:
                logger.debug("Broadcast callback failed", exc_info=True)

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        logger.info("Orchestrator started (window=%ds)", WINDOW_SECONDS)

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=10)
        logger.info("Orchestrator stopped")

    def force_train(self) -> bool:
        result = self.detector.train(force=True)
        if result:
            self._update_baseline()
            logger.info("Force-train completed")
        return result

    # ------------------------------------------------------------------

    def _run_loop(self):
        while not self._stop.is_set():
            try:
                self._tick()
            except Exception:
                logger.exception("Orchestrator tick failed")
            self._stop.wait(WINDOW_SECONDS)

    def _tick(self):
        now = datetime.now(timezone.utc)
        window_start = now - timedelta(seconds=WINDOW_SECONDS)
        window_end = now

        raw_events = self.collector.collect_all()
        self._persist_raw_events(raw_events)

        features = compute_features(raw_events, window_start, window_end)
        context = compute_context(raw_events)
        fw_id = self._persist_feature_window(
            features, context, window_start, window_end,
        )

        # --- baseline phase ---
        if not self.detector.is_trained:
            just_trained = self.detector.add_training_sample(features)
            if just_trained:
                self._update_baseline()
                logger.info("Model trained — switching to detection mode")
            else:
                logger.info(
                    "Baseline collection: %d / %d windows",
                    len(self.detector.training_data),
                    MIN_TRAINING_SAMPLES,
                )
            return

        # --- periodic retrain check ---
        hours_since = (now - self._last_retrain_time).total_seconds() / 3600
        if hours_since >= RETRAIN_INTERVAL_HOURS:
            self._periodic_retrain()

        # --- detection phase ---
        score, is_anomaly, top_feats = self.detector.score(features)
        alert_id = self._persist_alert(fw_id, score, is_anomaly, top_feats)

        self._broadcast("alert", {
            "alert_id": alert_id,
            "host_id": HOST_ID,
            "anomaly_score": score,
            "is_anomaly": is_anomaly,
            "top_features": top_feats,
            "timestamp": now.isoformat(),
        })

        if not is_anomaly:
            return

        recent = self._recent_alerts(minutes=15)
        alert_data = {
            "anomaly_score": score,
            "is_anomaly": is_anomaly,
            "features": features,
            "created_at": now,
            "host_id": HOST_ID,
        }
        result = self.correlator.evaluate(alert_data, recent)
        if result["should_create_incident"]:
            baseline = self._get_baseline()

            mitre_info = self.mitre_mapper.map_rules(result["triggered_rules"])

            connected_ips = list(
                (context or {}).get("top_connected_processes", {}).keys()
            )
            threat_hits = self.threat_enricher.check_local(connected_ips)

            explanation = self.llm_explainer.explain_incident_sync(
                host_id=HOST_ID,
                risk_score=result["risk_score"],
                severity=result["severity"],
                triggered_rules=result["triggered_rules"],
                alert_count=len([a for a in recent if a.get("is_anomaly")]),
                features=features,
                baseline=baseline,
                context=context,
                mitre_info=mitre_info,
                threat_intel_hits=threat_hits,
            )
            self._create_or_update_incident(
                alert_id, result, explanation, mitre_info, threat_hits,
            )

    # ------------------------------------------------------------------
    # DB helpers
    # ------------------------------------------------------------------

    def _persist_raw_events(self, events: List[Dict[str, Any]]):
        db = SessionLocal()
        try:
            for ev in events:
                db.add(RawEvent(
                    host_id=ev.get("host_id", HOST_ID),
                    event_type=ev.get("type", "unknown"),
                    timestamp=datetime.fromisoformat(ev["timestamp"]),
                    data=ev,
                ))
            db.commit()
        finally:
            db.close()

    def _persist_feature_window(
        self, features: Dict, context: Dict,
        window_start: datetime, window_end: datetime,
    ) -> int:
        db = SessionLocal()
        try:
            fw = FeatureWindow(
                host_id=HOST_ID,
                window_start=window_start,
                window_end=window_end,
                context=context,
                **{k: features[k] for k in FEATURE_NAMES},
            )
            db.add(fw)
            db.commit()
            db.refresh(fw)
            return fw.id
        finally:
            db.close()

    def _persist_alert(
        self, fw_id: int, score: float, is_anomaly: bool,
        top_features: Dict,
    ) -> int:
        db = SessionLocal()
        try:
            alert = Alert(
                host_id=HOST_ID,
                feature_window_id=fw_id,
                anomaly_score=score,
                is_anomaly=is_anomaly,
                top_features=top_features,
            )
            db.add(alert)
            db.commit()
            db.refresh(alert)
            return alert.id
        finally:
            db.close()

    def _recent_alerts(self, minutes: int = 15) -> List[Dict]:
        db = SessionLocal()
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
            rows = (
                db.query(Alert)
                .filter(Alert.host_id == HOST_ID, Alert.created_at >= cutoff)
                .order_by(Alert.created_at.desc())
                .all()
            )
            return [
                {
                    "id": r.id,
                    "anomaly_score": r.anomaly_score,
                    "is_anomaly": r.is_anomaly,
                    "created_at": r.created_at,
                }
                for r in rows
            ]
        finally:
            db.close()

    def _get_baseline(self) -> Dict[str, Any]:
        db = SessionLocal()
        try:
            bl = db.query(HostBaseline).filter_by(host_id=HOST_ID).first()
            return bl.feature_means if bl else {}
        finally:
            db.close()

    def _update_baseline(self):
        data = self.detector.training_data
        if not data:
            return
        arr = np.array(data)
        means = {
            name: round(float(arr[:, i].mean()), 4)
            for i, name in enumerate(FEATURE_NAMES)
        }
        stds = {
            name: round(float(arr[:, i].std()), 4)
            for i, name in enumerate(FEATURE_NAMES)
        }
        db = SessionLocal()
        try:
            bl = db.query(HostBaseline).filter_by(host_id=HOST_ID).first()
            if bl:
                bl.feature_means = means
                bl.feature_stds = stds
                bl.sample_count = len(data)
                bl.updated_at = datetime.now(timezone.utc)
            else:
                db.add(HostBaseline(
                    host_id=HOST_ID,
                    feature_means=means,
                    feature_stds=stds,
                    sample_count=len(data),
                ))
            db.commit()
        finally:
            db.close()

    def _periodic_retrain(self):
        """Retrain model on the last 24 hours of feature windows."""
        db = SessionLocal()
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
            recent_windows = (
                db.query(FeatureWindow)
                .filter(
                    FeatureWindow.host_id == HOST_ID,
                    FeatureWindow.window_start >= cutoff,
                )
                .all()
            )
            if len(recent_windows) < MIN_TRAINING_SAMPLES:
                return
            recent_data = [
                [float(getattr(w, name, 0)) for name in FEATURE_NAMES]
                for w in recent_windows
            ]
            if self.detector.retrain(recent_data):
                self._update_baseline()
                self._last_retrain_time = datetime.now(timezone.utc)
                logger.info("Periodic model retrain completed")
        finally:
            db.close()

    def _create_or_update_incident(
        self,
        alert_id: int,
        correlation: Dict,
        explanation: Dict,
        mitre_info: Optional[Dict] = None,
        threat_hits: Optional[List[Dict]] = None,
    ):
        db = SessionLocal()
        try:
            open_incident = (
                db.query(Incident)
                .filter(Incident.host_id == HOST_ID, Incident.status == "open")
                .order_by(Incident.created_at.desc())
                .first()
            )
            alert = db.get(Alert, alert_id)

            mitre_tactics = (mitre_info or {}).get("tactics", [])
            mitre_techniques = (mitre_info or {}).get("techniques", [])
            ti_hits = [h.get("ip", "") for h in (threat_hits or [])]

            if open_incident:
                open_incident.risk_score = max(
                    open_incident.risk_score, correlation["risk_score"],
                )
                open_incident.severity = correlation["severity"]
                open_incident.summary = explanation["summary"]
                open_incident.explanation = explanation["explanation"]
                open_incident.suggested_actions = explanation["suggested_actions"]
                open_incident.mitre_tactics = mitre_tactics
                open_incident.mitre_techniques = mitre_techniques
                open_incident.threat_intel_hits = ti_hits
                open_incident.updated_at = datetime.now(timezone.utc)
                if alert and alert not in open_incident.alerts:
                    open_incident.alerts.append(alert)
                incident_id = open_incident.id
            else:
                inc = Incident(
                    host_id=HOST_ID,
                    risk_score=correlation["risk_score"],
                    severity=correlation["severity"],
                    summary=explanation["summary"],
                    explanation=explanation["explanation"],
                    suggested_actions=explanation["suggested_actions"],
                    mitre_tactics=mitre_tactics,
                    mitre_techniques=mitre_techniques,
                    threat_intel_hits=ti_hits,
                )
                if alert:
                    inc.alerts.append(alert)
                db.add(inc)
                db.flush()
                incident_id = inc.id

            db.commit()

            self._broadcast("incident", {
                "incident_id": incident_id,
                "host_id": HOST_ID,
                "severity": correlation["severity"],
                "risk_score": correlation["risk_score"],
                "mitre_techniques": [t.get("id") for t in mitre_techniques],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
        finally:
            db.close()


# ------------------------------------------------------------------
# Module-level singleton
# ------------------------------------------------------------------

_instance: Orchestrator | None = None


def get_orchestrator() -> Orchestrator:
    global _instance
    if _instance is None:
        _instance = Orchestrator()
    return _instance
