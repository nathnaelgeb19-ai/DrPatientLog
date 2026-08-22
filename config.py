import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

DATA_DIR = os.environ.get("DATA_DIR") or os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

# Database configuration
#
# Local development:
#   No DATABASE_URL -> existing SQLite database
#
# Render / production:
#   DATABASE_URL -> Neon PostgreSQL
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()

if DATABASE_URL:
    DB_BACKEND = "postgresql"
    DB_FILE = None
else:
    DB_BACKEND = "sqlite"
    DB_FILE = os.path.join(DATA_DIR, "clinic_database.db")

SECRET_KEY = os.environ.get("SECRET_KEY") or "change-me-holy-bethel-clinic-secret"

CLINIC_NAME = "Holy Bethel Dental Clinic"
CLINIC_NAME_SHORT = "Holy Bethel"
DEFAULT_DOCTOR_NAME = "Dr. Nathnael Gebeyehu"

DAILY_REPORT_TIME = os.environ.get("DAILY_REPORT_TIME", "19:00")
MONTHLY_REPORT_TIME = os.environ.get("MONTHLY_REPORT_TIME", "19:00")
DEFAULT_BLOCK_DUP_TICKETS = False