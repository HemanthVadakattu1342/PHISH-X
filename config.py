import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-only-change-me")
    DATABASE_PATH = BASE_DIR / "instance" / "phishx.db"
    MAX_CONTENT_LENGTH = 2 * 1024 * 1024
