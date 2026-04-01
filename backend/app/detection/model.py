import hashlib
import hmac
import os
import logging
from typing import Dict, List, Tuple, Optional

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from app.config import FEATURE_NAMES, MODEL_PATH, MIN_TRAINING_SAMPLES, CONTAMINATION, JWT_SECRET

logger = logging.getLogger(__name__)

_shap_available = False
try:
    import shap
    _shap_available = True
except ImportError:
    logger.warning("shap not installed — falling back to z-score feature attribution")

_HMAC_SUFFIX = ".hmac"


def _compute_file_hmac(path: str) -> str:
    h = hmac.new(JWT_SECRET.encode(), digestmod=hashlib.sha256)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


class AnomalyDetector:
    """Isolation Forest anomaly detector with SHAP-based explainability."""

    def __init__(self):
        self.model: Optional[IsolationForest] = None
        self.explainer: Optional["shap.TreeExplainer"] = None
        self.is_trained: bool = False
        self.training_data: List[List[float]] = []
        self.feature_names = FEATURE_NAMES
        self._load_model()

    def _features_to_vector(self, features: Dict[str, float]) -> List[float]:
        return [float(features.get(name, 0)) for name in self.feature_names]

    # ------------------------------------------------------------------
    # Persistence (joblib + HMAC integrity)
    # ------------------------------------------------------------------

    def _load_model(self):
        if not os.path.exists(MODEL_PATH):
            return
        hmac_path = MODEL_PATH + _HMAC_SUFFIX
        if os.path.exists(hmac_path):
            expected = open(hmac_path).read().strip()
            actual = _compute_file_hmac(MODEL_PATH)
            if not hmac.compare_digest(expected, actual):
                logger.error(
                    "Model file HMAC mismatch — refusing to load potentially "
                    "tampered model at %s", MODEL_PATH,
                )
                return
        else:
            logger.warning("No HMAC file for model — loading without integrity check")
        try:
            data = joblib.load(MODEL_PATH)
            self.model = data["model"]
            self.training_data = data.get("training_data", [])
            self.is_trained = True
            self._build_explainer()
            logger.info("Loaded trained model with %d samples", len(self.training_data))
        except Exception as exc:
            logger.warning("Could not load model: %s", exc)

    def _save_model(self):
        os.makedirs(os.path.dirname(MODEL_PATH) or ".", exist_ok=True)
        joblib.dump(
            {"model": self.model, "training_data": self.training_data},
            MODEL_PATH,
        )
        sig = _compute_file_hmac(MODEL_PATH)
        with open(MODEL_PATH + _HMAC_SUFFIX, "w") as f:
            f.write(sig)

    def _build_explainer(self):
        if _shap_available and self.model is not None:
            try:
                self.explainer = shap.TreeExplainer(self.model)
            except Exception as exc:
                logger.warning("Could not build SHAP explainer: %s", exc)
                self.explainer = None

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def add_training_sample(self, features: Dict[str, float]) -> bool:
        """Append a sample; auto-train once MIN_TRAINING_SAMPLES is reached."""
        self.training_data.append(self._features_to_vector(features))
        if len(self.training_data) >= MIN_TRAINING_SAMPLES and not self.is_trained:
            return self.train()
        return False

    def train(self, force: bool = False) -> bool:
        if not force and len(self.training_data) < MIN_TRAINING_SAMPLES:
            return False
        if len(self.training_data) < 2:
            return False
        X = np.array(self.training_data)
        self.model = IsolationForest(
            n_estimators=100,
            contamination=CONTAMINATION,
            random_state=42,
        )
        self.model.fit(X)
        self.is_trained = True
        self._build_explainer()
        self._save_model()
        logger.info("Model trained on %d samples", len(self.training_data))
        return True

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def _shap_top_features(self, vector: np.ndarray) -> Dict[str, float]:
        """Use SHAP TreeExplainer to attribute anomaly to individual features."""
        if self.explainer is None:
            return self._zscore_top_features(vector)
        try:
            shap_values = self.explainer.shap_values(vector)
            if shap_values.ndim == 2:
                sv = shap_values[0]
            else:
                sv = shap_values
            attribution = {
                name: round(float(sv[i]), 4)
                for i, name in enumerate(self.feature_names)
            }
            top = dict(
                sorted(attribution.items(), key=lambda x: abs(x[1]), reverse=True)[:5]
            )
            return top
        except Exception as exc:
            logger.warning("SHAP attribution failed, falling back to z-score: %s", exc)
            return self._zscore_top_features(vector)

    def _zscore_top_features(self, vector: np.ndarray) -> Dict[str, float]:
        mean_vec = np.mean(self.training_data, axis=0)
        std_vec = np.std(self.training_data, axis=0) + 1e-10
        fv = vector[0] if vector.ndim == 2 else vector
        deviations = {
            name: round(abs(float(fv[i]) - float(mean_vec[i])) / float(std_vec[i]), 3)
            for i, name in enumerate(self.feature_names)
        }
        return dict(sorted(deviations.items(), key=lambda x: x[1], reverse=True)[:5])

    def score(self, features: Dict[str, float]) -> Tuple[float, bool, Dict[str, float]]:
        """Return (anomaly_score, is_anomaly, top_deviating_features).

        Feature attribution uses SHAP TreeExplainer when available, producing
        signed Shapley values.  Falls back to z-score distance otherwise.
        """
        if not self.is_trained or self.model is None:
            return 0.0, False, {}

        vector = np.array([self._features_to_vector(features)])
        raw_score = float(self.model.decision_function(vector)[0])
        anomaly_score = -raw_score
        is_anomaly = int(self.model.predict(vector)[0]) == -1

        top = self._shap_top_features(vector)

        return round(anomaly_score, 4), is_anomaly, top

    def retrain(self, data: List[List[float]]) -> bool:
        """Retrain on a fresh dataset (e.g. recent non-anomalous windows)."""
        if len(data) < 2:
            return False
        self.training_data = list(data)
        X = np.array(data)
        self.model = IsolationForest(
            n_estimators=100,
            contamination=CONTAMINATION,
            random_state=42,
        )
        self.model.fit(X)
        self.is_trained = True
        self._build_explainer()
        self._save_model()
        logger.info("Model retrained on %d samples", len(data))
        return True
