"""LLM-powered incident explanation via Ollama with template fallback."""

import logging
import os
from typing import Any

import httpx

from app.explanation.templates import AlertExplainer

logger = logging.getLogger(__name__)

OLLAMA_URL = os.environ.get("IDS_OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("IDS_OLLAMA_MODEL", "llama3")


def _build_analyst_prompt(
    host_id: str,
    risk_score: float,
    severity: str,
    triggered_rules: list[str],
    alert_count: int,
    features: dict[str, Any],
    baseline: dict[str, Any] | None,
    context: dict[str, Any] | None,
    mitre_info: dict | None = None,
    threat_intel_hits: list[dict] | None = None,
) -> str:
    feature_lines = "\n".join(
        f"  {k}: {v} (baseline: {(baseline or {}).get(k, 'N/A')})"
        for k, v in features.items()
    )

    ctx = context or {}
    context_lines = ""
    if ctx.get("top_new_processes"):
        context_lines += f"\nNew processes: {', '.join(ctx['top_new_processes'][:5])}"
    if ctx.get("top_connected_processes"):
        procs = [f"{n} ({c} conns)" for n, c in list(ctx["top_connected_processes"].items())[:5]]
        context_lines += f"\nTop connected processes: {', '.join(procs)}"

    mitre_section = ""
    if mitre_info and mitre_info.get("techniques"):
        techs = [f"{t['id']} ({t['name']})" for t in mitre_info["techniques"]]
        mitre_section = f"\nMITRE ATT&CK techniques: {', '.join(techs)}"

    ti_section = ""
    if threat_intel_hits:
        ti_lines = [f"  {h['ip']}: {h['detail']}" for h in threat_intel_hits]
        ti_section = "\nThreat intelligence hits:\n" + "\n".join(ti_lines)

    return f"""You are a senior SOC analyst. Analyze this security incident and provide:
1. A concise 2-3 sentence executive summary
2. A technical analysis paragraph explaining the attack pattern
3. Three specific recommended response actions

Incident Context:
  Host: {host_id}
  Severity: {severity.upper()}
  Risk Score: {risk_score}
  Correlated Alerts: {alert_count}
  Triggered Rules: {', '.join(triggered_rules)}

Feature Values (current vs baseline):
{feature_lines}
{context_lines}{mitre_section}{ti_section}

Respond in plain text with sections labeled SUMMARY, ANALYSIS, and ACTIONS.
Be specific and reference the actual feature values and processes observed."""


class OllamaExplainer:
    """Generates incident explanations via a local Ollama LLM.

    Falls back to the deterministic AlertExplainer if the LLM is
    unreachable or returns an error.
    """

    def __init__(self):
        self._fallback = AlertExplainer()
        self._client = httpx.AsyncClient(timeout=30.0)

    async def explain_incident(
        self,
        host_id: str,
        risk_score: float,
        severity: str,
        triggered_rules: list[str],
        alert_count: int,
        features: dict[str, Any],
        baseline: dict[str, Any] | None = None,
        context: dict[str, Any] | None = None,
        mitre_info: dict | None = None,
        threat_intel_hits: list[dict] | None = None,
    ) -> dict[str, str]:
        prompt = _build_analyst_prompt(
            host_id, risk_score, severity, triggered_rules, alert_count,
            features, baseline, context, mitre_info, threat_intel_hits,
        )

        try:
            resp = await self._client.post(
                f"{OLLAMA_URL}/api/generate",
                json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False},
            )
            resp.raise_for_status()
            llm_text = resp.json().get("response", "")
            if llm_text.strip():
                return self._parse_llm_response(llm_text, host_id, severity, risk_score)
        except Exception as exc:
            logger.warning("Ollama unavailable, using template fallback: %s", exc)

        return self._fallback.explain_incident(
            host_id=host_id,
            risk_score=risk_score,
            severity=severity,
            triggered_rules=triggered_rules,
            alert_count=alert_count,
            features=features,
            baseline=baseline,
            context=context,
        )

    def explain_incident_sync(
        self,
        host_id: str,
        risk_score: float,
        severity: str,
        triggered_rules: list[str],
        alert_count: int,
        features: dict[str, Any],
        baseline: dict[str, Any] | None = None,
        context: dict[str, Any] | None = None,
        mitre_info: dict | None = None,
        threat_intel_hits: list[dict] | None = None,
    ) -> dict[str, str]:
        """Synchronous version for use in the threaded orchestrator."""
        prompt = _build_analyst_prompt(
            host_id, risk_score, severity, triggered_rules, alert_count,
            features, baseline, context, mitre_info, threat_intel_hits,
        )

        try:
            with httpx.Client(timeout=30.0) as client:
                resp = client.post(
                    f"{OLLAMA_URL}/api/generate",
                    json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False},
                )
                resp.raise_for_status()
                llm_text = resp.json().get("response", "")
                if llm_text.strip():
                    return self._parse_llm_response(llm_text, host_id, severity, risk_score)
        except Exception as exc:
            logger.warning("Ollama unavailable, using template fallback: %s", exc)

        return self._fallback.explain_incident(
            host_id=host_id,
            risk_score=risk_score,
            severity=severity,
            triggered_rules=triggered_rules,
            alert_count=alert_count,
            features=features,
            baseline=baseline,
            context=context,
        )

    @staticmethod
    def _parse_llm_response(
        text: str, host_id: str, severity: str, risk_score: float,
    ) -> dict[str, str]:
        summary = f"Host {host_id} — {severity.upper()} severity (risk {risk_score})"
        explanation = text.strip()
        actions = ""

        sections = {"SUMMARY": "", "ANALYSIS": "", "ACTIONS": ""}
        current = None
        for line in text.split("\n"):
            upper = line.strip().upper().rstrip(":")
            if upper in sections:
                current = upper
                continue
            if current:
                sections[current] += line + "\n"

        if sections["SUMMARY"].strip():
            summary = sections["SUMMARY"].strip()
        if sections["ANALYSIS"].strip():
            explanation = sections["ANALYSIS"].strip()
        if sections["ACTIONS"].strip():
            actions = sections["ACTIONS"].strip()

        if not explanation:
            explanation = text.strip()

        return {
            "summary": summary,
            "explanation": explanation,
            "suggested_actions": actions or "- Investigate the host immediately.",
        }
