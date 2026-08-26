import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


class Config:
    SECRET_KEY = os.getenv("NETGUARDIAN_SECRET_KEY", "dev-only-change-me")
    DB_PATH = os.getenv("NETGUARDIAN_DB", str(BASE_DIR / "data" / "netguardian.db"))
    ADMIN_PASSWORD = os.getenv("NETGUARDIAN_ADMIN_PASSWORD", "admin123-change-me")
    CHECK_INTERVAL = int(os.getenv("NETGUARDIAN_CHECK_INTERVAL", "30"))
    CONNECT_TIMEOUT = float(os.getenv("NETGUARDIAN_CONNECT_TIMEOUT", "2.0"))
    HOST = os.getenv("NETGUARDIAN_HOST", "127.0.0.1")
    PORT = int(os.getenv("NETGUARDIAN_PORT", "5000"))
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.getenv("NETGUARDIAN_COOKIE_SECURE", "0") == "1"
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_SECONDS = 300
