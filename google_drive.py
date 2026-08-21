"""Google Drive backup helpers for the web clinic app."""
import os
import glob
from datetime import datetime

from config import DATA_DIR, CLINIC_NAME_SHORT

CREDENTIALS_FILE = os.path.join(DATA_DIR, "credentials.json")
TOKEN_FILE = os.path.join(DATA_DIR, "token.json")
SCOPES = ["https://www.googleapis.com/auth/drive.file"]


def credentials_present():
    return os.path.isfile(CREDENTIALS_FILE)


def is_connected():
    return os.path.isfile(TOKEN_FILE)


def _verifier_path(state):
    # Safe filename from state
    safe = "".join(c for c in (state or "x") if c.isalnum() or c in "-_")[:80]
    return os.path.join(DATA_DIR, f"oauth_verifier_{safe}.txt")


def _save_verifier(state, code_verifier):
    if not state or not code_verifier:
        return
    path = _verifier_path(state)
    with open(path, "w", encoding="utf-8") as f:
        f.write(code_verifier)


def _load_verifier(state):
    path = _verifier_path(state)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip() or None
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def _cleanup_old_verifiers():
    for p in glob.glob(os.path.join(DATA_DIR, "oauth_verifier_*.txt")):
        try:
            # remove files older than 1 hour
            if os.path.getmtime(p) < datetime.now().timestamp() - 3600:
                os.remove(p)
        except OSError:
            pass


def _load_creds():
    try:
        from google.oauth2.credentials import Credentials
        from google.auth.transport.requests import Request
    except ImportError:
        return None, (
            "Install: pip install google-api-python-client "
            "google-auth-oauthlib google-auth-httplib2"
        )

    if not os.path.isfile(TOKEN_FILE):
        return None, "Not connected to Google Drive yet."
    try:
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
            with open(TOKEN_FILE, "w", encoding="utf-8") as f:
                f.write(creds.to_json())
        if not creds or not creds.valid:
            return None, "Google login expired. Connect again."
        return creds, None
    except Exception as e:
        return None, str(e)


def get_auth_url(redirect_uri):
    """Return ({url, state, code_verifier}, error)."""
    if not credentials_present():
        return None, (
            "Missing credentials.json. Put OAuth Web client JSON in data/credentials.json"
        )
    try:
        from google_auth_oauthlib.flow import Flow
    except ImportError:
        return None, (
            "Install: pip install google-auth-oauthlib "
            "google-api-python-client google-auth-httplib2"
        )

    try:
        _cleanup_old_verifiers()
        flow = Flow.from_client_secrets_file(
            CREDENTIALS_FILE,
            scopes=SCOPES,
            redirect_uri=redirect_uri,
            autogenerate_code_verifier=True,
        )
        auth_url, state = flow.authorization_url(
            access_type="offline",
            prompt="consent",
        )
        verifier = getattr(flow, "code_verifier", None)
        # Fallback for some library versions
        if not verifier and hasattr(flow, "oauth2session"):
            verifier = getattr(flow.oauth2session, "code_verifier", None)

        if state and verifier:
            _save_verifier(state, verifier)

        return {
            "url": auth_url,
            "state": state,
            "code_verifier": verifier,
        }, None
    except Exception as e:
        return None, str(e)


def finish_auth(redirect_uri, authorization_response, code_verifier=None, state=None):
    """Exchange auth code for tokens. Uses file-backed verifier if session lost it."""
    try:
        from google_auth_oauthlib.flow import Flow
    except ImportError:
        return False, "Google libraries not installed."
    try:
        # Prefer session verifier; fall back to file saved at connect time
        if not code_verifier and state:
            code_verifier = _load_verifier(state)
        elif state:
            # load to clean up file even if session had verifier
            file_v = _load_verifier(state)
            if not code_verifier:
                code_verifier = file_v

        flow = Flow.from_client_secrets_file(
            CREDENTIALS_FILE,
            scopes=SCOPES,
            redirect_uri=redirect_uri,
            autogenerate_code_verifier=False,
        )
        if code_verifier:
            flow.code_verifier = code_verifier
        else:
            return False, (
                "Missing code verifier (OAuth session expired). "
                "Click Connect Google Drive again and finish without opening a new browser profile."
            )

        flow.fetch_token(authorization_response=authorization_response)
        creds = flow.credentials
        with open(TOKEN_FILE, "w", encoding="utf-8") as f:
            f.write(creds.to_json())
        return True, "Google Drive connected."
    except Exception as e:
        return False, str(e)


def disconnect():
    try:
        if os.path.isfile(TOKEN_FILE):
            os.remove(TOKEN_FILE)
        return True, "Disconnected from Google Drive."
    except Exception as e:
        return False, str(e)


def upload_file(local_path, remote_name=None):
    creds, err = _load_creds()
    if err:
        return False, err
    try:
        from googleapiclient.discovery import build
        from googleapiclient.http import MediaFileUpload
    except ImportError:
        return False, "Install google-api-python-client"

    if not remote_name:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        remote_name = f"{CLINIC_NAME_SHORT.replace(' ', '_')}_backup_{stamp}.db"

    try:
        service = build("drive", "v3", credentials=creds, cache_discovery=False)
        meta = {"name": remote_name}
        media = MediaFileUpload(
            local_path, mimetype="application/x-sqlite3", resumable=True
        )
        file = (
            service.files()
            .create(body=meta, media_body=media, fields="id, name, webViewLink")
            .execute()
        )
        link = file.get("webViewLink") or file.get("id")
        return True, f"Uploaded as {file.get('name')} ({link})"
    except Exception as e:
        return False, str(e)


def delete_old_backups(days=2):
    """Delete Holy Bethel automatic backup files older than the retention period."""
    creds, err = _load_creds()
    if err:
        return 0
    try:
        from googleapiclient.discovery import build
        from datetime import timezone
        service = build("drive", "v3", credentials=creds, cache_discovery=False)
        cutoff = datetime.now(timezone.utc).timestamp() - (days * 24 * 60 * 60)
        deleted = 0
        page_token = None
        while True:
            result = service.files().list(
                q="trashed = false and name contains 'Holy_Bethel_backup_' and mimeType = 'application/x-sqlite3'",
                fields="nextPageToken, files(id,name,createdTime)",
                pageToken=page_token,
                spaces="drive",
            ).execute()
            for item in result.get("files", []):
                try:
                    created = datetime.fromisoformat(item["createdTime"].replace("Z", "+00:00")).timestamp()
                    if created < cutoff:
                        service.files().delete(fileId=item["id"]).execute()
                        deleted += 1
                except Exception:
                    continue
            page_token = result.get("nextPageToken")
            if not page_token:
                break
        return deleted
    except Exception:
        return 0
