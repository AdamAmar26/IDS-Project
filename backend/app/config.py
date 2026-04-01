import logging
import os
import socket
import warnings

_logger = logging.getLogger(__name__)

TESTING = os.environ.get("IDS_TESTING", "").lower() in ("1", "true", "yes")

HOST_ID = os.environ.get("IDS_HOST_ID", socket.gethostname())
DB_PATH = os.environ.get("IDS_DB_PATH", "data/ids.db")
WINDOW_SECONDS = int(os.environ.get("IDS_WINDOW_SECONDS", "30"))
API_HOST = os.environ.get("IDS_API_HOST", "0.0.0.0")
API_PORT = int(os.environ.get("IDS_API_PORT", "8000"))
MODEL_PATH = os.environ.get("IDS_MODEL_PATH", "data/isolation_forest.joblib")
MIN_TRAINING_SAMPLES = int(os.environ.get("IDS_MIN_TRAINING_SAMPLES", "20"))
CONTAMINATION = float(os.environ.get("IDS_CONTAMINATION", "0.05"))
RETRAIN_INTERVAL_HOURS = int(os.environ.get("IDS_RETRAIN_HOURS", "24"))
API_KEY = os.environ.get("IDS_API_KEY", "")

OLLAMA_URL = os.environ.get("IDS_OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("IDS_OLLAMA_MODEL", "llama3")

JWT_SECRET = os.environ.get("IDS_JWT_SECRET", "change-me-in-production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = int(os.environ.get("IDS_JWT_EXPIRE_MINUTES", "60"))
ADMIN_USERNAME = os.environ.get("IDS_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("IDS_ADMIN_PASSWORD", "admin")

CORS_ORIGINS: list[str] = [
    o.strip()
    for o in os.environ.get("IDS_CORS_ORIGINS", "http://localhost:3000").split(",")
    if o.strip()
]

AUTH_RATE_LIMIT = os.environ.get("IDS_AUTH_RATE_LIMIT", "10/minute")

RAW_EVENT_RETENTION_DAYS = int(os.environ.get("IDS_RAW_EVENT_RETENTION_DAYS", "7"))
FEATURE_WINDOW_RETENTION_DAYS = int(
    os.environ.get("IDS_FEATURE_WINDOW_RETENTION_DAYS", "30")
)

_INSECURE_JWT_SECRETS = {"change-me-in-production", ""}
_INSECURE_PASSWORDS = {"admin", "password", ""}


def validate_security_defaults() -> None:
    """Raise on insecure defaults outside of test mode."""
    if TESTING:
        return
    if JWT_SECRET in _INSECURE_JWT_SECRETS:
        warnings.warn(
            "IDS_JWT_SECRET is using an insecure default — set a strong secret "
            "via the IDS_JWT_SECRET environment variable before deploying.",
            stacklevel=2,
        )
        _logger.critical("JWT_SECRET is insecure — change IDS_JWT_SECRET immediately")
    if ADMIN_PASSWORD in _INSECURE_PASSWORDS:
        warnings.warn(
            "IDS_ADMIN_PASSWORD is using an insecure default — set a strong "
            "password via the IDS_ADMIN_PASSWORD environment variable.",
            stacklevel=2,
        )
        _logger.critical(
            "ADMIN_PASSWORD is insecure — change IDS_ADMIN_PASSWORD immediately"
        )


FEATURE_NAMES = [
    "failed_login_count",
    "successful_login_count",
    "unique_dest_ips",
    "unique_dest_ports",
    "outbound_conn_count",
    "bytes_sent",
    "bytes_received",
    "avg_process_cpu",
    "new_process_count",
    "inbound_outbound_ratio",
    "unusual_hour_flag",
    "privileged_process_count",
    "parent_child_anomaly_score",
    "dns_query_count",
    "unique_parent_processes",
    "memory_usage_spike",
    "sensitive_file_access_count",
]
