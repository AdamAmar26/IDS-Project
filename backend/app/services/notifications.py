from __future__ import annotations

import smtplib
from email.mime.text import MIMEText

import httpx

from app.config import (
    ALERT_EMAIL_FROM,
    ALERT_EMAIL_TO,
    GENERIC_WEBHOOK_URL,
    SMTP_HOST,
    SMTP_PASSWORD,
    SMTP_PORT,
    SMTP_USER,
    TEAMS_WEBHOOK_URL,
)
from app.db.models import NotificationDelivery
from app.db.session import SessionLocal


class NotificationDispatcher:
    def _record(self, incident_id: int, channel: str, ok: bool, error: str = "") -> None:
        db = SessionLocal()
        try:
            db.add(
                NotificationDelivery(
                    incident_id=incident_id,
                    channel=channel,
                    status="sent" if ok else "failed",
                    error=error or None,
                )
            )
            db.commit()
        finally:
            db.close()

    @staticmethod
    def _payload(incident_id: int, payload: dict) -> dict:
        return {
            "incident_id": incident_id,
            "host_id": payload.get("host_id"),
            "severity": payload.get("severity"),
            "risk_score": payload.get("risk_score"),
            "summary": payload.get("summary", ""),
            "timestamp": payload.get("timestamp"),
        }

    def _post_with_retry(self, url: str, body: dict) -> tuple[bool, str]:
        for _ in range(2):
            try:
                with httpx.Client(timeout=8.0) as client:
                    resp = client.post(url, json=body)
                if 200 <= resp.status_code < 300:
                    return True, ""
                err = f"status={resp.status_code} body={resp.text[:200]}"
            except Exception as exc:  # pragma: no cover - network dependent
                err = str(exc)
        return False, err

    def send_incident_created(self, incident_id: int, payload: dict) -> None:
        common = self._payload(incident_id, payload)

        if TEAMS_WEBHOOK_URL:
            teams_body = {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "summary": f"IDS incident #{incident_id}",
                "themeColor": "ff4d4f",
                "title": f"IDS Incident #{incident_id} ({common['severity']})",
                "text": (
                    f"Host: {common['host_id']}\n\n"
                    f"Risk score: {common['risk_score']}\n\n"
                    f"Summary: {common['summary'] or 'No summary'}"
                ),
            }
            ok, err = self._post_with_retry(TEAMS_WEBHOOK_URL, teams_body)
            self._record(incident_id, "teams", ok, err)

        if GENERIC_WEBHOOK_URL:
            ok, err = self._post_with_retry(GENERIC_WEBHOOK_URL, common)
            self._record(incident_id, "webhook", ok, err)

        if SMTP_HOST and ALERT_EMAIL_TO and ALERT_EMAIL_FROM:
            subject = f"[IDS] Incident #{incident_id} {common['severity']}"
            body = (
                f"Host: {common['host_id']}\n"
                f"Risk score: {common['risk_score']}\n"
                f"Summary: {common['summary'] or 'No summary'}\n"
                f"Time: {common['timestamp']}\n"
            )
            msg = MIMEText(body, "plain")
            msg["Subject"] = subject
            msg["From"] = ALERT_EMAIL_FROM
            msg["To"] = ALERT_EMAIL_TO
            try:
                with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=8) as server:
                    server.starttls()
                    if SMTP_USER:
                        server.login(SMTP_USER, SMTP_PASSWORD)
                    server.sendmail(ALERT_EMAIL_FROM, [ALERT_EMAIL_TO], msg.as_string())
                self._record(incident_id, "email", True)
            except Exception as exc:  # pragma: no cover - network dependent
                self._record(incident_id, "email", False, str(exc))

    def send_test(self) -> dict:
        payload = {
            "host_id": "test-host",
            "severity": "medium",
            "risk_score": 4,
            "summary": "Test incident notification from IDS settings endpoint.",
            "timestamp": "now",
        }
        self.send_incident_created(0, payload)
        return {
            "teams_configured": bool(TEAMS_WEBHOOK_URL),
            "webhook_configured": bool(GENERIC_WEBHOOK_URL),
            "email_configured": bool(SMTP_HOST and ALERT_EMAIL_TO and ALERT_EMAIL_FROM),
        }
