import os
import sys

os.environ.setdefault("IDS_TESTING", "true")
os.environ.setdefault("IDS_JWT_SECRET", "test-secret-not-for-production")
os.environ.setdefault("IDS_ADMIN_PASSWORD", "test-password")
os.environ.setdefault("IDS_DB_PATH", ":memory:")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
