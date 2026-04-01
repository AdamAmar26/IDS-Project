import os
import socket

HOST_ID = os.environ.get("IDS_HOST_ID", socket.gethostname())
DB_PATH = os.environ.get("IDS_DB_PATH", "data/ids.db")
WINDOW_SECONDS = int(os.environ.get("IDS_WINDOW_SECONDS", "30"))
API_HOST = os.environ.get("IDS_API_HOST", "0.0.0.0")
API_PORT = int(os.environ.get("IDS_API_PORT", "8000"))
MODEL_PATH = os.environ.get("IDS_MODEL_PATH", "data/isolation_forest.pkl")
MIN_TRAINING_SAMPLES = int(os.environ.get("IDS_MIN_TRAINING_SAMPLES", "20"))
CONTAMINATION = float(os.environ.get("IDS_CONTAMINATION", "0.05"))
RETRAIN_INTERVAL_HOURS = int(os.environ.get("IDS_RETRAIN_HOURS", "24"))
API_KEY = os.environ.get("IDS_API_KEY", "")

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
]
