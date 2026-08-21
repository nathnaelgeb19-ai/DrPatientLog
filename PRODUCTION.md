# Production deployment checklist

This build intentionally excludes the optional clinical expansion/odontogram phase. It keeps the existing patient/history workflow while hardening authentication, backup, deployment, and UI behavior.

## First launch
A new installation has **no default admin credentials**. Open `/setup` and create the first administrator with a strong password and recovery email.

## Secure email password recovery
Configure these environment variables:
- `APP_BASE_URL`
- `SMTP_HOST`
- `SMTP_PORT` (normally 587)
- `SMTP_USERNAME`
- `SMTP_PASSWORD`
- `SMTP_FROM`

Reset links are single-use and expire after 30 minutes. The database stores only a hash of the reset token.

## Production secret
Set `APP_ENV=production`, `SECRET_KEY` to a long random value, and `SESSION_COOKIE_SECURE=1` when serving over HTTPS.

## Scheduler
Run the web service and scheduler as separate processes. Do not start APScheduler from Flask requests.

Example process types:
- `web: gunicorn app:app --bind 0.0.0.0:$PORT --workers 1 --threads 4`
- `worker: python scheduler.py`

The worker handles automatic backups, Telegram reports, and the Telegram outbox. This avoids duplicate jobs when the web application uses multiple workers.

## Backup
- Automatic local backup time is configurable in the UI.
- Local backup location is configurable in the UI.
- Google Drive can be connected from Backup Center.
- Automatic backups are retained for two days by default.
- Use the Test automatic backup button after configuring the destination.

## Roles
- `admin`: doctor management, backup/recovery, audit and clinic settings.
- `doctor`: normal clinical/practice workflow.

## CSRF
Authenticated POST forms receive a session-bound CSRF token automatically from the base template. Login/setup/password-recovery forms are intentionally exempt because they establish authentication state.

## HTTPS
Use HTTPS in production. Never expose the Flask development server directly to the internet.
