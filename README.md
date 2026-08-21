# Holy Bethel Dental Clinic — Web App

Web version of the clinic manager so **Telegram reports can run 24/7** without keeping a PC on.

## What Phase 1 includes

- Login (doctor accounts)
- Dashboard (today / Ethiopian month stats)
- New patient + history (search / date filter)
- Suggest fee from procedure presets
- Ethiopian date conversion
- Telegram settings + send daily report
- Outbox retry + scheduled daily job (server time)
- Audit log
- Base salary setting
- Premium doctor management page with active-doctor profile editing and secure credential updates
- Local computer backup: consistent SQLite snapshots downloadable directly from the web UI
- Google Drive backup and full database restore with automatic safety copy

## Default login (change after first use)

- Username: `admin`
- Password: `admin123`

## Run on your computer (test)

```bash
cd holy_bethel_web
python -m venv venv
# Windows: venv\Scripts\activate
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000

## Deploy free/cheap (example: Render)

1. Create a free account at https://render.com  
2. New → **Web Service** → connect a GitHub repo with this folder  
3. Settings:
   - **Build command:** `pip install -r requirements.txt`
   - **Start command:** `gunicorn app:app --bind 0.0.0.0:$PORT --workers 1 --threads 4`
4. Environment variables:
   - `SECRET_KEY` = long random string
   - `TZ` = `Africa/Addis_Ababa`
   - `DAILY_REPORT_TIME` = `19:00` (optional)
5. Add a **persistent disk** mounted at `/data` and set `DATA_DIR=/data`  
   (Without a disk, free hosts can wipe SQLite on redeploy.)

### Important about free tiers

Many free plans **sleep** after idle time. When asleep, scheduled Telegram jobs pause until the next web request.  
Options:

- Use a paid always-on instance (small cost), or  
- Use a free “cron ping” (e.g. cron-job.org) every 10 minutes to hit your URL so the service stays warm  

## Data note

This web app uses its **own** database on the server. It does not automatically read the Windows desktop `.db`.
Go to **Backup → Restore from full database backup** to upload a previous `.db` file and replace
the current database (patients, doctors, Telegram settings, everything). A safety copy of the
database being replaced is kept on the server automatically.

## IMPORTANT — stop losing your Telegram token / Google Drive link on every update

Both are stored as files on disk (`data/clinic_database.db` and `data/token.json`). Render's
free web service filesystem is **wiped on every redeploy** unless you attach a persistent disk.
Do this once and the problem goes away for good:

1. Render dashboard → your service → **Disks** → **Add Disk**
   - Mount path: `/data`
   - Size: 1 GB is plenty to start
2. Environment → add `DATA_DIR` = `/data`
3. Also set `SECRET_KEY` to a long random string (Environment → Add Environment Variable).
   Without this, the app falls back to a hardcoded key, which is why old login sessions can
   look "stuck" across deploys — cookies signed with the same fallback key keep validating
   even after the server has effectively reset.
4. Redeploy once after adding the disk. From then on, `clinic_database.db`, the Telegram
   token/chat ID (stored inside the DB), and `data/token.json` (Google Drive) will all persist
   across every future deploy.

If you're on a different host than Render, the same rule applies: point `DATA_DIR` at a
persistent volume, not the ephemeral app filesystem.

## Backup architecture

The web application keeps the live SQLite database on the server/persistent disk. A browser cannot silently write files into an arbitrary folder on a user's computer, so **Backup Center → Download clinic backup** creates a consistent `.db` snapshot and downloads it through the browser. The doctor can then move that file to an external drive or secure local storage.

For hosted deployments, attach a persistent disk to the server. The local download is an additional disaster-recovery copy; it does not replace persistent server storage.

## Current management features

- Active doctor profile editing directly from **Doctors**
- Username and optional password update
- Multiple doctor accounts with switch/delete controls
- Local SQLite snapshot download
- Google Drive upload
- Full database restore with a pre-restore safety copy
- Patient CSV import/export
