"""Google Drive backup helpers for the web clinic app.

Supports:
- Local credentials.json during development
- GOOGLE_CLIENT_SECRET_JSON environment variable on Render
- OAuth PKCE flow
- Persistent OAuth token storage in the SQLite settings table
- Google Drive uploads
- Automatic deletion of old backups
"""

import os
import glob
import json
from datetime import datetime

from config import DATA_DIR, CLINIC_NAME_SHORT
from db import get_setting, set_setting


CREDENTIALS_FILE = os.path.join(DATA_DIR, "credentials.json")
TOKEN_FILE = os.path.join(DATA_DIR, "token.json")

GOOGLE_CLIENT_SECRET_JSON = os.environ.get(
    "GOOGLE_CLIENT_SECRET_JSON",
    ""
)

GOOGLE_TOKEN_SETTING = "google_drive_token"

SCOPES = [
    "https://www.googleapis.com/auth/drive.file"
]


def _get_client_config():
    """Return Google OAuth client configuration.

    Render:
        Uses GOOGLE_CLIENT_SECRET_JSON.

    Local development:
        Falls back to data/credentials.json.
    """
    if GOOGLE_CLIENT_SECRET_JSON:
        try:
            return json.loads(GOOGLE_CLIENT_SECRET_JSON)
        except json.JSONDecodeError as e:
            raise RuntimeError(
                f"GOOGLE_CLIENT_SECRET_JSON contains invalid JSON: {e}"
            )

    if not os.path.isfile(CREDENTIALS_FILE):
        return None

    try:
        with open(CREDENTIALS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        raise RuntimeError(
            f"Could not read Google credentials.json: {e}"
        )


def credentials_present():
    """Return True when Google OAuth client credentials exist."""
    if GOOGLE_CLIENT_SECRET_JSON.strip():
        return True

    return os.path.isfile(CREDENTIALS_FILE)


def is_connected():
    """Return True when a Google OAuth token is stored."""
    try:
        token = get_setting(GOOGLE_TOKEN_SETTING, "")
        return bool((token or "").strip())
    except Exception:
        return False


def _verifier_path(state):
    """Return safe filesystem path for temporary OAuth verifier."""
    safe = "".join(
        c for c in (state or "x")
        if c.isalnum() or c in "-_"
    )[:80]

    return os.path.join(
        DATA_DIR,
        f"oauth_verifier_{safe}.txt"
    )


def _save_verifier(state, code_verifier):
    """Persist PKCE verifier temporarily."""
    if not state or not code_verifier:
        return

    path = _verifier_path(state)

    with open(path, "w", encoding="utf-8") as f:
        f.write(code_verifier)


def _load_verifier(state):
    """Load and remove temporary PKCE verifier."""
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
    """Remove OAuth verifier files older than one hour."""
    for path in glob.glob(
        os.path.join(DATA_DIR, "oauth_verifier_*.txt")
    ):
        try:
            if (
                os.path.getmtime(path)
                < datetime.now().timestamp() - 3600
            ):
                os.remove(path)
        except OSError:
            pass


def _load_creds():
    """Load Google credentials from the persistent database token."""
    try:
        from google.oauth2.credentials import Credentials
        from google.auth.transport.requests import Request
    except ImportError:
        return None, (
            "Install: pip install google-api-python-client "
            "google-auth-oauthlib google-auth-httplib2"
        )

    token_json = get_setting(
        GOOGLE_TOKEN_SETTING,
        ""
    )

    if not token_json:
        return None, "Not connected to Google Drive yet."

    try:
        token_data = json.loads(token_json)

        creds = Credentials.from_authorized_user_info(
            token_data,
            SCOPES
        )

        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())

            # Persist refreshed token back into SQLite.
            set_setting(
                GOOGLE_TOKEN_SETTING,
                creds.to_json()
            )

        if not creds or not creds.valid:
            return None, "Google login expired. Connect again."

        return creds, None

    except Exception as e:
        return None, str(e)


def get_auth_url(redirect_uri):
    """Return ({url, state, code_verifier}, error)."""
    if not credentials_present():
        return None, (
            "Google OAuth credentials are missing. "
            "On Render set GOOGLE_CLIENT_SECRET_JSON. "
            "For local development put OAuth Web client JSON "
            "in data/credentials.json."
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

        client_config = _get_client_config()

        flow = Flow.from_client_config(
            client_config,
            scopes=SCOPES,
            redirect_uri=redirect_uri,
            autogenerate_code_verifier=True,
        )

        auth_url, state = flow.authorization_url(
            access_type="offline",
            prompt="consent",
        )

        verifier = getattr(
            flow,
            "code_verifier",
            None
        )

        # Fallback for some library versions.
        if (
            not verifier
            and hasattr(flow, "oauth2session")
        ):
            verifier = getattr(
                flow.oauth2session,
                "code_verifier",
                None
            )

        if state and verifier:
            _save_verifier(
                state,
                verifier
            )

        return {
            "url": auth_url,
            "state": state,
            "code_verifier": verifier,
        }, None

    except Exception as e:
        return None, str(e)


def finish_auth(
    redirect_uri,
    authorization_response,
    code_verifier=None,
    state=None,
):
    """Exchange OAuth authorization code for persistent token."""
    try:
        from google_auth_oauthlib.flow import Flow
    except ImportError:
        return False, "Google libraries not installed."

    try:
        # Prefer the session verifier.
        if not code_verifier and state:
            code_verifier = _load_verifier(state)

        elif state:
            # Clean up the file-backed verifier.
            file_verifier = _load_verifier(state)

            if not code_verifier:
                code_verifier = file_verifier

        if not code_verifier:
            return False, (
                "Missing code verifier (OAuth session expired). "
                "Click Connect Google Drive again and finish "
                "without opening a new browser profile."
            )

        client_config = _get_client_config()

        flow = Flow.from_client_config(
            client_config,
            scopes=SCOPES,
            redirect_uri=redirect_uri,
            autogenerate_code_verifier=False,
        )

        flow.code_verifier = code_verifier

        flow.fetch_token(
            authorization_response=authorization_response
        )

        creds = flow.credentials

        # IMPORTANT:
        # Store the OAuth token in SQLite so Render restarts
        # do not destroy the Google Drive connection.
        set_setting(
            GOOGLE_TOKEN_SETTING,
            creds.to_json()
        )

        return True, "Google Drive connected."

    except Exception as e:
        return False, str(e)


def disconnect():
    """Remove persistent Google Drive authorization."""
    try:
        set_setting(
            GOOGLE_TOKEN_SETTING,
            ""
        )

        # Remove old file-based token if one exists.
        if os.path.isfile(TOKEN_FILE):
            try:
                os.remove(TOKEN_FILE)
            except OSError:
                pass

        return True, "Disconnected from Google Drive."

    except Exception as e:
        return False, str(e)


def upload_file(local_path, remote_name=None):
    """Upload a database backup to Google Drive."""
    creds, err = _load_creds()

    if err:
        return False, err

    try:
        from googleapiclient.discovery import build
        from googleapiclient.http import MediaFileUpload
    except ImportError:
        return False, (
            "Install google-api-python-client"
        )

    if not remote_name:
        stamp = datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        )

        remote_name = os.path.basename(local_path)

    try:
        service = build(
            "drive",
            "v3",
            credentials=creds,
            cache_discovery=False,
        )

        metadata = {
            "name": remote_name
        }

        media = MediaFileUpload(
            local_path,
            mimetype="application/sql",
            resumable=True,
        )

        file = (
            service.files()
            .create(
                body=metadata,
                media_body=media,
                fields="id,name,webViewLink",
            )
            .execute()
        )

        link = (
            file.get("webViewLink")
            or file.get("id")
        )

        return True, (
            f"Uploaded as {file.get('name')} "
            f"({link})"
        )

    except Exception as e:
        return False, str(e)


def delete_old_backups(days=2):
    """Delete automatic Google Drive backups older than days."""
    creds, err = _load_creds()

    if err:
        return 0

    try:
        from googleapiclient.discovery import build
        from datetime import timezone

        service = build(
            "drive",
            "v3",
            credentials=creds,
            cache_discovery=False,
        )

        cutoff = (
            datetime.now(timezone.utc).timestamp()
            - (days * 24 * 60 * 60)
        )

        deleted = 0
        page_token = None

        while True:
            result = (
                service.files()
                .list(
                    q=(
                        "trashed = false "
                        "and name contains "
                        "'Holy_Bethel_backup_' "
                        "and mimeType = "
                        "'application/x-sqlite3'"
                    ),
                    fields=(
                        "nextPageToken, "
                        "files(id,name,createdTime)"
                    ),
                    pageToken=page_token,
                    spaces="drive",
                )
                .execute()
            )

            for item in result.get("files", []):
                try:
                    created = datetime.fromisoformat(
                        item["createdTime"].replace(
                            "Z",
                            "+00:00"
                        )
                    ).timestamp()

                    if created < cutoff:
                        service.files().delete(
                            fileId=item["id"]
                        ).execute()

                        deleted += 1

                except Exception:
                    continue

            page_token = result.get(
                "nextPageToken"
            )

            if not page_token:
                break

        return deleted

    except Exception:
        return 0