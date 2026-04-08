from fastapi import APIRouter, Depends

from app.api.deps import require_jwt
from app.config import (
    ALERT_EMAIL_FROM,
    ALERT_EMAIL_TO,
    GENERIC_WEBHOOK_URL,
    SMTP_HOST,
    TEAMS_WEBHOOK_URL,
)
from app.services.audit import log_audit_event
from app.services.notifications import NotificationDispatcher

router = APIRouter()


@router.get("/notifications")
def get_notification_settings(_: str = Depends(require_jwt)):
    return {
        "teams_configured": bool(TEAMS_WEBHOOK_URL),
        "generic_webhook_configured": bool(GENERIC_WEBHOOK_URL),
        "email_configured": bool(SMTP_HOST and ALERT_EMAIL_TO and ALERT_EMAIL_FROM),
    }


@router.post("/notifications/test")
def test_notifications(actor: str = Depends(require_jwt)):
    result = NotificationDispatcher().send_test()
    log_audit_event(actor, "notification.test", "settings.notifications", result)
    return {"ok": True, **result}
