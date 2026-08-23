"""
Holy Bethel Dental Clinic â€” Web application
Runs 24/7 on a free/cheap host (Render, Railway, etc.)
"""
from datetime import datetime, timedelta
import hashlib
import secrets
import smtplib
from email.message import EmailMessage
from functools import wraps
import os
import csv
import io

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    jsonify,
    Response,
    make_response,
)
from apscheduler.schedulers.background import BackgroundScheduler

from config import SECRET_KEY, CLINIC_NAME, CLINIC_NAME_SHORT, DAILY_REPORT_TIME, MONTHLY_REPORT_TIME, DB_BACKEND, DATABASE_URL
from db import (
    init_db,
    authenticate,
    get_conn,
    get_doctor,
    log_audit,
    queue_telegram,
    pending_outbox,
    mark_outbox_sent,
    mark_outbox_fail,
    PROCEDURE_PRESETS,
    list_doctors,
    get_setting,
    set_setting,
    ticket_exists,
    delete_doctor,
    set_doctor_credentials,
    update_doctor_profile,
    tr,
    set_doctor_email,
    create_password_reset_token,
    create_local_password_reset_token,
    reset_password_with_token,
)
from config import DB_FILE, DATA_DIR
from ethiopian import get_ethiopian_date, is_ethiopian_month_end, ETH_MONTHS
from telegram_util import (
    build_daily_report,
    build_earning_message,
    try_send_for_doctor,
    send_telegram_document,
)

# Optional newer telegram helpers (monthly / delete) if present
try:
    from telegram_util import build_monthly_report, build_delete_message
except ImportError:
    build_monthly_report = None
    build_delete_message = None
def _execute(obj, query, params=()):
    if DB_BACKEND == "postgresql":
        query = query.replace("?", "%s")
        query = query.replace("telegram_enabled=1", "telegram_enabled=TRUE")
    return obj.execute(query, params) if params else obj.execute(query)

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
)

if not SECRET_KEY or SECRET_KEY.startswith("change-me-"):
    if os.environ.get("APP_ENV", "development") == "production":
        # Local development can still run without a configured secret; production cannot.
        raise RuntimeError("Set a strong SECRET_KEY environment variable before production deployment.")

init_db()


BACKUP_DIR = os.path.join(DATA_DIR, "backups")
os.makedirs(BACKUP_DIR, exist_ok=True)

def _get_backup_dir():
    """Return the persisted automatic-backup folder, creating it when possible."""
    configured = (get_setting("automatic_backup_dir", "") or "").strip()
    path = os.path.abspath(os.path.expanduser(configured)) if configured else BACKUP_DIR
    try:
        os.makedirs(path, exist_ok=True)
    except Exception:
        path = BACKUP_DIR
        os.makedirs(path, exist_ok=True)
    return path


def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not session.get("doctor_id"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapped


def admin_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        doc = current_doctor()
        if not doc:
            return redirect(url_for("login"))
        if doc.get("role") != "admin":
            flash("Administrator permission is required for this section.", "error")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return wrapped


def current_doctor():
    did = session.get("doctor_id")
    return get_doctor(did) if did else None


def _csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


@app.before_request
def _validate_csrf():
    if request.method == "POST" and request.endpoint not in {"login", "setup", "forgot_password", "reset_password"}:
        token = request.form.get("csrf_token", "")
        if not token or not secrets.compare_digest(token, session.get("csrf_token", "")):
            return Response("Invalid or missing CSRF token.", status=400)


@app.context_processor
def inject_globals():
    lang = get_setting("ui_language", "en") or "en"
    return {
        "clinic_name": CLINIC_NAME,
        "clinic_short": CLINIC_NAME_SHORT,
        "doctor": current_doctor(),
        "presets": list(PROCEDURE_PRESETS.keys()),
        "lang": lang,
        "t": lambda k: tr(k, lang),
        "csrf_token": _csrf_token(),
    }


@app.route("/health")
def health():
    return jsonify({"status": "ok"}), 200
    
@app.route("/")
def index():
    # The application entry point always requires authentication.  This is
    # intentional for shared/hosted clinic deployments: an old browser
    # session must never make the dashboard appear without the login screen.
    session.clear()
    return redirect(url_for("login"))


@app.route("/setup", methods=["GET", "POST"])
def setup():
    if get_setting("setup_required", "0") != "1":
        return redirect(url_for("login"))
    if request.method == "POST":
        try:
            name = request.form.get("name", "").strip()
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            confirm = request.form.get("confirm_password", "")
            email = request.form.get("email", "").strip()
            if not name or not username or not email:
                raise ValueError("Name, username and recovery email are required.")
            if len(password) < 8:
                raise ValueError("Password must be at least 8 characters.")
            if password != confirm:
                raise ValueError("Passwords do not match.")
            from db import add_doctor
            doctor_id = add_doctor(name, 45000, username, password, 0, email, "admin")
            set_setting("active_doctor_id", doctor_id)
            set_setting("setup_required", "0")
            flash("Administrator account created. Please sign in.", "success")
            return redirect(url_for("login"))
        except Exception as e:
            flash(str(e), "error")
    return render_template("setup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if get_setting("setup_required", "0") == "1":
        return redirect(url_for("setup"))
    # Never silently bypass the login page when an old session exists.
    # Successful authentication below creates a fresh session.
    if request.method == "POST":
        user = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        doc = authenticate(user, password)
        if doc:
            session.clear()
            session["doctor_id"] = doc["id"]
            session["doctor_name"] = doc["name"]
            session.permanent = False  # ends when browser closes
            flash(f"Signed in as {doc['name']}", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid username or password", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Signed out", "info")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    doctor_id = session["doctor_id"]
    today = datetime.now().strftime("%Y-%m-%d")
    eth = get_ethiopian_date(today)
    parts = eth.split()
    m, y = (parts[0], parts[2]) if len(parts) >= 3 else ("", "")
    stats_range = request.args.get("range") or get_setting("stats_range", "eth_month") or "eth_month"
    if request.args.get("range"):
        set_setting("stats_range", stats_range)

    with get_conn() as conn:
        today_cut = _execute(conn,
            "SELECT COALESCE(SUM(my_earning),0) AS s FROM patients WHERE doctor_id=? AND greg_date=?",
            (doctor_id, today),
        ).fetchone()["s"]
        all_rows = _execute(conn,
            "SELECT greg_date, eth_date, total_fee, my_earning FROM patients WHERE doctor_id=?",
            (doctor_id,),
        ).fetchall()
        recent = _execute(conn,
            "SELECT * FROM patients WHERE doctor_id=? ORDER BY id DESC LIMIT 8",
            (doctor_id,),
        ).fetchall()

    week_ago = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d")
    count = income = cut = 0.0
    for r in all_rows:
        g = r["greg_date"] or ""
        e = r["eth_date"] or ""
        include = False
        if stats_range == "today":
            include = g == today
        elif stats_range == "week":
            include = g >= week_ago
        elif stats_range == "all":
            include = True
        else:  # eth_month
            include = bool(m and y and m in e and y in e)
        if include:
            count += 1
            income += float(r["total_fee"] or 0)
            cut += float(r["my_earning"] or 0)

    return render_template(
        "dashboard.html",
        today_cut=today_cut,
        month_count=int(count),
        month_income=income,
        month_cut=cut,
        eth_today=eth,
        recent=recent,
        stats_range=stats_range,
    )


@app.route("/patients")
@login_required
def patients():
    doctor_id = session["doctor_id"]
    q = request.args.get("q", "").strip().lower()
    date_from = request.args.get("from", "").strip()
    date_to = request.args.get("to", "").strip()
    with get_conn() as conn:
        rows = _execute(conn,
            """
            SELECT * FROM patients WHERE doctor_id=? ORDER BY id DESC LIMIT 500
            """,
            (doctor_id,),
        ).fetchall()
    filtered = []
    for r in rows:
        text = f"{r['patient_name']} {r['ticket_no']} {r['procedure']} {r['eth_date']}".lower()
        if q and q not in text:
            continue
        g = r["greg_date"] or ""
        if date_from and g and g < date_from:
            continue
        if date_to and g and g > date_to:
            continue
        filtered.append(r)
    return render_template("patients.html", patients=filtered, q=q, date_from=date_from, date_to=date_to)


@app.route("/patients/new", methods=["GET", "POST"])
@login_required
def patient_new():
    doctor_id = session["doctor_id"]
    today = datetime.now().strftime("%Y-%m-%d")
    if request.method == "POST":
        greg = request.form.get("greg_date", today).strip()
        eth = request.form.get("eth_date") or get_ethiopian_date(greg)
        patient = request.form.get("patient_name", "").strip().title()
        ticket = request.form.get("ticket_no", "").strip().upper()
        procedure = request.form.get("procedure", "").strip().title()
        try:
            fee = float(request.form.get("total_fee") or 0)
            pct = float(request.form.get("doctor_pct") or 4)
        except ValueError:
            flash("Fee and cut % must be numbers", "error")
            return redirect(url_for("patient_new"))
        if not patient or not procedure:
            flash("Patient name and procedure are required", "error")
            return redirect(url_for("patient_new"))
        if get_setting("block_duplicate_tickets", "0") == "1" and ticket:
            if ticket_exists(ticket, doctor_id):
                flash(f"Ticket {ticket} already exists (duplicates blocked).", "error")
                return redirect(url_for("patient_new"))
        cut = fee * (pct / 100.0)
        with get_conn() as conn:
            if DB_BACKEND == "postgresql":
                cur = _execute(conn,
                    """
                    INSERT INTO patients
                    (greg_date, eth_date, patient_name, ticket_no, procedure,
                     total_fee, doctor_pct, my_earning, doctor_id)
                    VALUES (?,?,?,?,?,?,?,?,?)
                    RETURNING id
                    """,
                    (greg, eth, patient, ticket, procedure, fee, pct, cut, doctor_id),
                )
                new_id = cur.fetchone()["id"]
            else:
                cur = _execute(conn,
                    """
                    INSERT INTO patients
                    (greg_date, eth_date, patient_name, ticket_no, procedure,
                     total_fee, doctor_pct, my_earning, doctor_id)
                    VALUES (?,?,?,?,?,?,?,?,?)
                    """,
                    (greg, eth, patient, ticket, procedure, fee, pct, cut, doctor_id),
                )
                new_id = cur.lastrowid
        log_audit(
            doctor_id,
            session.get("doctor_name", ""),
            "create",
            entity_id=new_id,
            detail=f"{patient} - {procedure} - {fee:,.2f}",
        )
        try:
            msg = build_earning_message(
                "New patient record", eth, ticket, patient, procedure, fee, cut, doctor_id
            )
        except TypeError:
            msg = build_earning_message(eth, ticket, patient, procedure, fee, cut, doctor_id)
        ok, detail = try_send_for_doctor(doctor_id, msg)
        if not ok:
            queue_telegram(doctor_id, msg)
        flash(f"Saved {patient}" + (" - Telegram sent" if ok else " - Telegram queued"), "success")
        return redirect(url_for("patients"))

    return render_template(
        "patient_form.html",
        mode="new",
        greg=today,
        eth=get_ethiopian_date(today),
        record=None,
    )


@app.route("/patients/<int:pid>/edit", methods=["GET", "POST"])
@login_required
def patient_edit(pid):
    doctor_id = session["doctor_id"]
    with get_conn() as conn:
        row = _execute(conn,
            "SELECT * FROM patients WHERE id=? AND doctor_id=?", (pid, doctor_id)
        ).fetchone()
    if not row:
        flash("Record not found", "error")
        return redirect(url_for("patients"))
    if request.method == "POST":
        greg = request.form.get("greg_date", "").strip()
        eth = request.form.get("eth_date") or get_ethiopian_date(greg)
        patient = request.form.get("patient_name", "").strip().title()
        ticket = request.form.get("ticket_no", "").strip().upper()
        procedure = request.form.get("procedure", "").strip().title()
        try:
            fee = float(request.form.get("total_fee") or 0)
            pct = float(request.form.get("doctor_pct") or 4)
        except ValueError:
            flash("Fee and cut % must be numbers", "error")
            return redirect(url_for("patient_edit", pid=pid))
        if get_setting("block_duplicate_tickets", "0") == "1" and ticket:
            if ticket_exists(ticket, doctor_id, exclude_id=pid):
                flash(f"Ticket {ticket} already exists (duplicates blocked).", "error")
                return redirect(url_for("patient_edit", pid=pid))
        cut = fee * (pct / 100.0)
        with get_conn() as conn:
            _execute(conn,
                """UPDATE patients SET greg_date=?, eth_date=?, patient_name=?, ticket_no=?,
                   procedure=?, total_fee=?, doctor_pct=?, my_earning=?
                   WHERE id=? AND doctor_id=?""",
                (greg, eth, patient, ticket, procedure, fee, pct, cut, pid, doctor_id),
            )
        log_audit(
            doctor_id, session.get("doctor_name", ""), "update",
            entity_id=pid, detail=f"{patient} - {procedure} - {fee:,.2f}",
        )
        try:
            msg = build_earning_message(
                "Record updated", eth, ticket, patient, procedure, fee, cut, doctor_id
            )
        except TypeError:
            msg = build_earning_message(eth, ticket, patient, procedure, fee, cut, doctor_id)
        ok, _ = try_send_for_doctor(doctor_id, msg)
        if not ok:
            queue_telegram(doctor_id, msg)
        flash("Record updated", "success")
        return redirect(url_for("patients"))
    return render_template(
        "patient_form.html", mode="edit", greg=row["greg_date"],
        eth=row["eth_date"], record=row,
    )


@app.route("/patients/<int:pid>/delete", methods=["POST"])
@login_required
def patient_delete(pid):
    doctor_id = session["doctor_id"]
    name = None
    with get_conn() as conn:
        row = _execute(conn,
            "SELECT * FROM patients WHERE id=? AND doctor_id=?",
            (pid, doctor_id),
        ).fetchone()
        if row:
            name = row["patient_name"]
            _execute(conn,"DELETE FROM patients WHERE id=?", (pid,))
    # Audit + Telegram after connection closes (avoids SQLite "database is locked")
    if name is not None:
        log_audit(
            doctor_id,
            session.get("doctor_name", ""),
            "delete",
            entity_id=pid,
            detail=name,
        )
        if build_delete_message:
            msg = build_delete_message(name, 1)
            ok, _ = try_send_for_doctor(doctor_id, msg)
            if not ok:
                queue_telegram(doctor_id, msg)
        flash("Record deleted", "info")
    else:
        flash("Not found", "error")
    return redirect(url_for("patients"))


@app.route("/patients/export.csv")
@login_required
def patients_export_csv():
    doctor_id = session["doctor_id"]
    with get_conn() as conn:
        rows = _execute(conn,
            "SELECT * FROM patients WHERE doctor_id=? ORDER BY id", (doctor_id,)
        ).fetchall()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["ID", "Gregorian", "Ethiopian", "Patient", "Ticket", "Procedure",
                "Fee", "Pct", "Cut", "Created"])
    for r in rows:
        w.writerow([r["id"], r["greg_date"], r["eth_date"], r["patient_name"],
                    r["ticket_no"], r["procedure"], r["total_fee"], r["doctor_pct"],
                    r["my_earning"], r["created_at"]])
    resp = make_response(chr(65279) + buf.getvalue())
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = (
        f"attachment; filename=patients_{datetime.now():%Y%m%d}.csv"
    )
    return resp


@app.route("/patients/<int:pid>/receipt")
@login_required
def patient_receipt(pid):
    doctor_id = session["doctor_id"]
    with get_conn() as conn:
        r = _execute(conn,
            "SELECT * FROM patients WHERE id=? AND doctor_id=?", (pid, doctor_id)
        ).fetchone()
    if not r:
        flash("Not found", "error")
        return redirect(url_for("patients"))
    html = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>Receipt</title>
<style>
body{{font-family:Segoe UI,sans-serif;background:#f1f1ef;padding:40px}}
.card{{max-width:480px;margin:auto;background:#fff;padding:28px;border-radius:12px;border:1px solid #e1e1df}}
h2{{color:#55616c;margin:0 0 8px;border-bottom:3px solid #b98a3e;padding-bottom:12px}}
.row{{display:flex;justify-content:space-between;margin:8px 0}}
.total{{background:linear-gradient(135deg,#b98a3e,#9c7433);color:#fff;padding:14px;border-radius:10px;text-align:center;margin-top:16px}}
@media print{{button{{display:none}}}}
</style></head><body><div class="card">
<h2>Dental {CLINIC_NAME}</h2>
<p>Treatment Receipt - {session.get('doctor_name','')}</p>
<div class="row"><span>Receipt</span><strong>#REC-{r['id']:05d}</strong></div>
<div class="row"><span>Gregorian</span><strong>{r['greg_date']}</strong></div>
<div class="row"><span>Ethiopian</span><strong>{r['eth_date']}</strong></div>
<div class="row"><span>Patient</span><strong>{r['patient_name']}</strong></div>
<div class="row"><span>Ticket</span><strong>{r['ticket_no'] or 'N/A'}</strong></div>
<div class="row"><span>Procedure</span><strong>{r['procedure']}</strong></div>
<div class="total"><div>Price paid</div><strong style="font-size:1.4rem">{float(r['total_fee'] or 0):,.2f} ETB</strong></div>
<p style="text-align:center;margin-top:16px"><button onclick="window.print()">Print</button></p>
</div></body></html>"""
    return Response(html, mimetype="text/html")


@app.route("/monthly")
@login_required
def monthly():
    doctor_id = session["doctor_id"]
    with get_conn() as conn:
        rows = _execute(conn,
            "SELECT eth_date, total_fee, my_earning FROM patients WHERE doctor_id=?",
            (doctor_id,),
        ).fetchall()
        doc = _execute(conn,
            "SELECT base_salary FROM doctors WHERE id=?", (doctor_id,)
        ).fetchone()
    base = float(doc["base_salary"] if doc else 45000)
    months = {}
    for r in rows:
        parts = (r["eth_date"] or "").split()
        if len(parts) < 3:
            continue
        key = (parts[0], parts[2])
        months.setdefault(key, {"count": 0, "income": 0.0, "cut": 0.0})
        months[key]["count"] += 1
        months[key]["income"] += float(r["total_fee"] or 0)
        months[key]["cut"] += float(r["my_earning"] or 0)
    eth = get_ethiopian_date()
    parts = eth.split()
    if len(parts) >= 3:
        months.setdefault((parts[0], parts[2]), {"count": 0, "income": 0.0, "cut": 0.0})

    def sort_key(item):
        m, y = item[0]
        try:
            yi = int(y)
        except ValueError:
            yi = 0
        try:
            mi = ETH_MONTHS.index(m)
        except ValueError:
            mi = 99
        return (yi, mi)

    ordered = []
    for (m, y), vals in sorted(months.items(), key=sort_key, reverse=True):
        ordered.append({
            "label": f"{m} {y}", "count": vals["count"], "income": vals["income"],
            "cut": vals["cut"], "base": base, "take": base + vals["cut"],
        })
    return render_template("monthly.html", months=ordered)


@app.route("/monthly/send", methods=["POST"])
@login_required
def monthly_send():
    doctor_id = session["doctor_id"]
    if not build_monthly_report:
        flash("Monthly report not available", "error")
        return redirect(url_for("monthly"))
    text, label = build_monthly_report(doctor_id)
    if not text:
        flash("Could not build monthly report", "error")
        return redirect(url_for("monthly"))
    ok, detail = try_send_for_doctor(doctor_id, text)
    if not ok:
        queue_telegram(doctor_id, text)
        flash(f"Queued: {detail}", "error")
    else:
        flash(f"Monthly report for {label} sent", "success")
    return redirect(url_for("monthly"))


@app.route("/doctors", methods=["GET", "POST"])
@login_required
@admin_required
def doctors_manage():
    doctor_id = session["doctor_id"]
    if request.method == "POST":
        action = request.form.get("action")
        try:
            if action == "add":
                from db import add_doctor
                add_doctor(
                    request.form.get("name", ""),
                    float(request.form.get("base_salary") or 45000),
                    request.form.get("username", ""),
                    request.form.get("password", ""),
                    int(request.form.get("birth_year") or 0),
                    request.form.get("email", ""),
                    request.form.get("role", "doctor"),
                )
                flash("Doctor added successfully.", "success")

            elif action == "edit_active":
                doc = get_doctor(doctor_id)
                if not doc:
                    raise ValueError("Active doctor was not found.")
                name = (request.form.get("name") or "").strip()
                if not name:
                    raise ValueError("Doctor name is required.")
                update_doctor_profile(
                    doctor_id,
                    name=name,
                    base_salary=float(request.form.get("base_salary") or doc["base_salary"] or 45000),
                    birth_year=int(request.form.get("birth_year") or 0),
                )
                set_doctor_email(doctor_id, request.form.get("email", ""))
                set_doctor_credentials(
                    doctor_id,
                    request.form.get("username") or doc.get("username") or "",
                    request.form.get("password") or None,
                )
                session["doctor_name"] = name
                log_audit(
                    doctor_id, name, "update", entity="doctor", entity_id=doctor_id,
                    detail="Updated active doctor profile and credentials."
                )
                flash("Active doctor information updated.", "success")

            elif action == "switch":
                new_id = int(request.form.get("doctor_id"))
                doc = get_doctor(new_id)
                if doc:
                    session["doctor_id"] = doc["id"]
                    session["doctor_name"] = doc["name"]
                    flash(f"Switched to {doc['name']}.", "success")
                else:
                    raise ValueError("Doctor not found.")

            elif action == "delete":
                delete_doctor(int(request.form.get("doctor_id")), doctor_id)
                flash("Doctor deleted.", "info")
        except Exception as e:
            flash(str(e), "error")
        return redirect(url_for("doctors_manage"))

    try:
        docs = list_doctors()
    except Exception:
        docs = [get_doctor(doctor_id)] if get_doctor(doctor_id) else []
    active_doc = get_doctor(doctor_id)
    return render_template(
        "doctors_manage.html",
        doctors=docs,
        active_id=doctor_id,
        active_doc=active_doc,
    )

@app.route("/forgot", methods=["GET", "POST"])
def forgot_password():
    reset_link = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        birth_year = request.form.get("birth_year", "").strip()
        email = request.form.get("email", "").strip().lower()

        try:
            info = create_local_password_reset_token(
                username,
                birth_year,
                email
            )

            if not info:
                flash(
                    "The username, birth year, and recovery email do not match our records.",
                    "error"
                )
            else:
                reset_link = url_for(
                    "reset_password",
                    token=info["token"],
                    _external=True
                )
                flash(
                    "Identity verified. Use the one-time reset link below. "
                    "It expires in 30 minutes.",
                    "success"
                )

        except Exception as e:
            flash(str(e), "error")

    return render_template(
        "forgot.html",
        reset_link=reset_link
    )

@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    token = request.args.get("token", "") if request.method == "GET" else request.form.get("token", "")
    if request.method == "POST":
        try:
            password = request.form.get("password", "")
            confirm = request.form.get("confirm_password", "")
            if password != confirm:
                raise ValueError("Passwords do not match.")
            reset_password_with_token(token, password)
            flash("Password reset successfully. You can now sign in.", "success")
            return redirect(url_for("login"))
        except Exception as e:
            flash(str(e), "error")
    return render_template("reset_password.html", token=token)


def _send_password_reset_email(recipient, name, token):
    host = os.environ.get("SMTP_HOST", "").strip()
    port = int(os.environ.get("SMTP_PORT", "587"))
    user = os.environ.get("SMTP_USERNAME", "").strip()
    password = os.environ.get("SMTP_PASSWORD", "")
    sender = os.environ.get("SMTP_FROM", user).strip()
    base_url = os.environ.get("APP_BASE_URL", "").rstrip("/")
    if not host or not sender or not base_url:
        raise RuntimeError("SMTP_HOST, SMTP_FROM and APP_BASE_URL must be configured for email recovery.")
    link = f"{base_url}{url_for('reset_password')}?token={token}"
    msg = EmailMessage()
    msg["Subject"] = f"{CLINIC_NAME} â€” password reset"
    msg["From"] = sender
    msg["To"] = recipient
    msg.set_content(f"Hello {name},\n\nUse the link below to reset your {CLINIC_NAME} password. This link expires in 30 minutes and can only be used once.\n\n{link}\n\nIf you did not request this, you can ignore this email.\n")
    with smtplib.SMTP(host, port, timeout=20) as smtp:
        smtp.starttls()
        if user:
            smtp.login(user, password)
        smtp.send_message(msg)


@app.route("/api/eth-date")
@login_required
def api_eth_date():
    g = request.args.get("greg", "")
    return jsonify({"eth": get_ethiopian_date(g)})


@app.route("/api/suggest-fee")
@login_required
def api_suggest_fee():
    proc = request.args.get("procedure", "").strip().title()
    fee = PROCEDURE_PRESETS.get(proc)
    return jsonify({"fee": fee})


@app.route("/telegram", methods=["GET", "POST"])
@login_required
def telegram_settings():
    doctor_id = session["doctor_id"]
    doc = get_doctor(doctor_id)
    if request.method == "POST":
        token = request.form.get("token", "").strip()
        chat = request.form.get("chat_id", "").strip()
        enabled = 1 if request.form.get("enabled") == "on" else 0
        daily_t = request.form.get("daily_time", "19:00").strip() or "19:00"
        monthly_t = request.form.get("monthly_time", "19:00").strip() or "19:00"
        with get_conn() as conn:
            _execute(conn,
                """
                UPDATE doctors SET telegram_bot_token=?, telegram_chat_id=?, telegram_enabled=?
                WHERE id=?
                """,
                (token, chat, enabled, doctor_id),
            )
        set_setting("telegram_daily_report_time", daily_t)
        set_setting("telegram_monthly_report_time", monthly_t)
        flash("Telegram settings saved", "success")
        return redirect(url_for("telegram_settings"))
    return render_template(
        "telegram.html",
        doc=doc,
        daily_time=get_setting("telegram_daily_report_time", "19:00"),
        monthly_time=get_setting("telegram_monthly_report_time", "19:00"),
    )


@app.route("/telegram/send-daily", methods=["POST"])
@login_required
def telegram_send_daily():
    doctor_id = session["doctor_id"]
    text = build_daily_report(doctor_id)
    ok, detail = try_send_for_doctor(doctor_id, text)
    if not ok:
        queue_telegram(doctor_id, text)
        flash(f"Queued (send failed: {detail})", "error")
    else:
        flash("Daily report sent", "success")
    return redirect(url_for("telegram_settings"))


@app.route("/settings/doctors", methods=["GET", "POST"])
@login_required
@admin_required
def doctors_settings():
    doctor_id = session["doctor_id"]
    doc = get_doctor(doctor_id)
    if request.method == "POST":
        action = request.form.get("action") or "profile"
        try:
            if action == "password":
                set_doctor_credentials(
                    doctor_id,
                    request.form.get("username") or doc.get("username") or "",
                    request.form.get("password") or None,
                )
                flash("Login credentials updated", "success")
            else:
                update_doctor_profile(
                    doctor_id,
                    name=request.form.get("name") or doc["name"],
                    base_salary=float(request.form.get("base_salary") or 45000),
                    birth_year=int(request.form.get("birth_year") or 0),
                )
                set_doctor_email(doctor_id, request.form.get("email", ""))
                session["doctor_name"] = request.form.get("name") or doc["name"]
                flash("Profile updated", "success")
        except Exception as e:
            flash(str(e), "error")
        return redirect(url_for("doctors_settings"))
    return render_template(
        "doctors.html",
        doc=get_doctor(doctor_id),
        block_dup=get_setting("block_duplicate_tickets", "0") == "1",
        ui_lang=get_setting("ui_language", "en"),
    )


@app.route("/settings/app", methods=["POST"])
@login_required
@admin_required
def app_settings_save():
    set_setting(
        "block_duplicate_tickets",
        "1" if request.form.get("block_dup") == "on" else "0",
    )
    lang = request.form.get("ui_language", "en")
    if lang not in ("en", "am"):
        lang = "en"
    set_setting("ui_language", lang)
    flash("App settings saved", "success")
    return redirect(url_for("doctors_settings"))


def _create_backup_snapshot():
    """Create a consistent database backup in the configured backup folder."""
    backup_dir = _get_backup_dir()
    os.makedirs(backup_dir, exist_ok=True)

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if DB_BACKEND == "postgresql":
        import subprocess

        target_path = os.path.join(
            backup_dir,
            f"holy_bethel_backup_{stamp}.sql",
        )

        try:
            result = subprocess.run(
                [
                    "pg_dump",
                    DATABASE_URL,
                    "--no-owner",
                    "--no-privileges",
                    "-f",
                    target_path,
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )

            if result.returncode != 0:
                raise RuntimeError(
                    result.stderr.strip() or "pg_dump failed."
                )

            return target_path

        except FileNotFoundError:
            raise RuntimeError(
                "PostgreSQL backup requires pg_dump, but pg_dump was not found on this computer."
            )

    else:
        import sqlite3

        target_path = os.path.join(
            backup_dir,
            f"holy_bethel_backup_{stamp}.db",
        )

        source = sqlite3.connect(DB_FILE, timeout=30)
        target = sqlite3.connect(target_path)

        try:
            with target:
                source.backup(target)
        finally:
            target.close()
            source.close()

        return target_path


def _cleanup_local_backups():
    """Keep only backups from the last two days."""
    import glob
    cutoff = datetime.now().timestamp() - (2 * 24 * 60 * 60)
    removed = 0
    for path in glob.glob(os.path.join(_get_backup_dir(), "holy_bethel_backup_*.db")):
        try:
            if os.path.getmtime(path) < cutoff:
                os.remove(path)
                removed += 1
        except OSError:
            pass
    return removed


def _cleanup_google_backups():
    """Delete Google Drive automatic backups older than two days."""
    try:
        import google_drive as gdrive
        return gdrive.delete_old_backups(days=2)
    except Exception:
        return 0


def _run_automatic_backup():
    """Create local backup, upload to Google Drive, and send to Telegram."""
    if DB_BACKEND == "sqlite" and not os.path.isfile(DB_FILE):
        return False, "Database file not found."

    try:
        # 1. Create a consistent SQLite snapshot
        path = _create_backup_snapshot()

        # 2. Clean up old local backups
        local_removed = _cleanup_local_backups()

        # 3. Google Drive backup
        drive_msg = "Google Drive not connected."

        try:
            import google_drive as gdrive

            if gdrive.is_connected():
                drive_ok, drive_msg = gdrive.upload_file(path)
                _cleanup_google_backups()

        except Exception as e:
            drive_msg = f"Google Drive error: {e}"

        # 4. Telegram database backup
        telegram_msg = "Telegram backup not configured."

        try:
            with get_conn() as conn:
                doctors = _execute(conn,
                    """
                    SELECT id, name, telegram_bot_token, telegram_chat_id
                    FROM doctors
                    WHERE telegram_enabled=1
                      AND telegram_bot_token!=''
                      AND telegram_chat_id!=''
                    """
                ).fetchall()

            if doctors:
                sent_count = 0
                failed_count = 0
                last_error = ""

                for doctor in doctors:
                    caption = (
                        f"🔐 <b>{CLINIC_NAME}</b>\n"
                        f"<b>Automatic database backup</b>\n"
                        f"📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                        f"💾 {os.path.basename(path)}"
                    )

                    ok, detail = send_telegram_document(
                        doctor["telegram_bot_token"],
                        doctor["telegram_chat_id"],
                        path,
                        caption="",
                    )

                    if ok:
                        sent_count += 1
                    else:
                        failed_count += 1
                        last_error = detail

                if sent_count:
                    telegram_msg = f"Telegram backup sent to {sent_count} account(s)."

                if failed_count:
                    telegram_msg += f" {failed_count} failed."
                    if last_error:
                        telegram_msg += f" Last error: {last_error}"

        except Exception as e:
            telegram_msg = f"Telegram backup error: {e}"

        return True, (
            f"Backup created: {os.path.basename(path)}. "
            f"Local old backups removed: {local_removed}. "
            f"{drive_msg} "
            f"{telegram_msg}"
        )

    except Exception as e:
        return False, f"Automatic backup failed: {e}"


@app.route("/cron/automatic-backup", methods=["GET", "POST"])
def cron_automatic_backup():
    """
    Secure endpoint for Render Cron Jobs.

    Authentication:
      CRON_SECRET environment variable
      Header: X-Cron-Secret
      or query parameter: ?key=
    """
    import hmac

    configured_secret = (os.environ.get("CRON_SECRET") or "").strip()

    if not configured_secret:
        return jsonify({
            "ok": False,
            "error": "CRON_SECRET is not configured on the server."
        }), 503

    supplied_secret = (
        request.headers.get("X-Cron-Secret")
        or request.args.get("key")
        or ""
    ).strip()

    if not supplied_secret or not hmac.compare_digest(
        supplied_secret,
        configured_secret
    ):
        return jsonify({
            "ok": False,
            "error": "Unauthorized"
        }), 401

    try:
        ok, message = _run_automatic_backup()

        if ok:
            return jsonify({
                "ok": True,
                "message": message,
                "timestamp": datetime.now().isoformat(timespec="seconds")
            }), 200

        return jsonify({
            "ok": False,
            "message": message,
            "timestamp": datetime.now().isoformat(timespec="seconds")
        }), 500

    except Exception as e:
        return jsonify({
            "ok": False,
            "error": str(e),
            "timestamp": datetime.now().isoformat(timespec="seconds")
        }), 500
@app.route("/cron/daily-report", methods=["GET", "POST"])
def cron_daily_report():
    """
    Secure endpoint for Render Daily Telegram Report Cron Job.

    Render calls this endpoint every minute. The endpoint checks the
    configured daily report time using Ethiopia local time and sends
    the report only when the configured time is reached.
    """
    import hmac

    configured_secret = (os.environ.get("CRON_SECRET") or "").strip()

    if not configured_secret:
        return jsonify({
            "ok": False,
            "error": "CRON_SECRET is not configured on the server."
        }), 503

    supplied_secret = (
        request.headers.get("X-Cron-Secret")
        or request.args.get("key")
        or ""
    ).strip()

    if not supplied_secret or not hmac.compare_digest(
        supplied_secret,
        configured_secret
    ):
        return jsonify({
            "ok": False,
            "error": "Unauthorized"
        }), 401

    try:
        from zoneinfo import ZoneInfo

        now = datetime.now(ZoneInfo("Africa/Addis_Ababa"))
        current_time = now.strftime("%H:%M")

        configured_time = (
            get_setting(
                "telegram_daily_report_time",
                DAILY_REPORT_TIME
            )
            or DAILY_REPORT_TIME
        ).strip()

        if current_time != configured_time:
            return jsonify({
                "ok": True,
                "skipped": True,
                "reason": "Not the configured daily report time.",
                "current_time": current_time,
                "configured_time": configured_time
            }), 200

        _scheduled_daily()

        return jsonify({
            "ok": True,
            "message": "Daily Telegram report executed.",
            "timestamp": now.isoformat(timespec="seconds")
        }), 200

    except Exception as e:
        return jsonify({
            "ok": False,
            "error": str(e),
            "timestamp": datetime.now().isoformat(timespec="seconds")
        }), 500


@app.route("/cron/monthly-report", methods=["GET", "POST"])
def cron_monthly_report():
    """
    Secure endpoint for Render Monthly Telegram Report Cron Job.

    Render calls this endpoint every minute. The endpoint checks the
    configured monthly report time and Ethiopian month-end before sending.
    """
    import hmac

    configured_secret = (os.environ.get("CRON_SECRET") or "").strip()

    if not configured_secret:
        return jsonify({
            "ok": False,
            "error": "CRON_SECRET is not configured on the server."
        }), 503

    supplied_secret = (
        request.headers.get("X-Cron-Secret")
        or request.args.get("key")
        or ""
    ).strip()

    if not supplied_secret or not hmac.compare_digest(
        supplied_secret,
        configured_secret
    ):
        return jsonify({
            "ok": False,
            "error": "Unauthorized"
        }), 401

    try:
        from zoneinfo import ZoneInfo

        now = datetime.now(ZoneInfo("Africa/Addis_Ababa"))
        current_time = now.strftime("%H:%M")

        configured_time = (
            get_setting(
                "telegram_monthly_report_time",
                MONTHLY_REPORT_TIME
            )
            or MONTHLY_REPORT_TIME
        ).strip()

        if current_time != configured_time:
            return jsonify({
                "ok": True,
                "skipped": True,
                "reason": "Not the configured monthly report time.",
                "current_time": current_time,
                "configured_time": configured_time
            }), 200

        today = now.strftime("%Y-%m-%d")

        if not is_ethiopian_month_end(today):
            return jsonify({
                "ok": True,
                "skipped": True,
                "reason": "Today is not Ethiopian month-end.",
                "date": today
            }), 200

        _scheduled_monthly()

        return jsonify({
            "ok": True,
            "message": "Monthly Telegram report executed.",
            "timestamp": now.isoformat(timespec="seconds")
        }), 200

    except Exception as e:
        return jsonify({
            "ok": False,
            "error": str(e),
            "timestamp": datetime.now().isoformat(timespec="seconds")
        }), 500

@app.route("/backup")
@login_required
@admin_required
def backup_page():
    try:
        import google_drive as gdrive
        gdrive_creds = gdrive.credentials_present()
        gdrive_connected = gdrive.is_connected()
    except Exception:
        gdrive_creds = False
        gdrive_connected = False

    return render_template(
        "backup.html",
        gdrive_creds=gdrive_creds,
        gdrive_connected=gdrive_connected,
        backup_dir=_get_backup_dir(),
        backup_time=get_setting("automatic_backup_time", "19:00"),
        DB_BACKEND=DB_BACKEND,
    )


@app.route("/backup/location", methods=["POST"])
@login_required
@admin_required
def backup_location():
    """Save the server-side folder used for automatic database backups."""
    raw = (request.form.get("backup_dir") or "").strip()
    if not raw:
        flash("Enter a folder path for automatic backups.", "error")
        return redirect(url_for("backup_page"))
    path = os.path.abspath(os.path.expanduser(raw))
    try:
        os.makedirs(path, exist_ok=True)
        probe = os.path.join(path, ".backup_write_test")
        with open(probe, "w", encoding="utf-8") as f:
            f.write("ok")
        os.remove(probe)
        set_setting("automatic_backup_dir", path)
        flash(f"Automatic backup location saved: {path}", "success")
        log_audit(session["doctor_id"], session.get("doctor_name", ""), "backup",
                  entity="settings", detail=f"Changed automatic backup location to {path}")
    except Exception as e:
        flash(f"That folder cannot be used by the server: {e}", "error")
    return redirect(url_for("backup_page"))

@app.route("/backup/location/browse", methods=["POST"])
@login_required
@admin_required
def backup_location_browse():
    """Open a native folder chooser when the Flask server runs on a desktop."""
    try:
        import tkinter as tk
        from tkinter import filedialog
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        selected = filedialog.askdirectory(title="Choose automatic backup folder")
        root.destroy()
        if not selected:
            flash("Folder selection cancelled.", "info")
            return redirect(url_for("backup_page"))
        path = os.path.abspath(selected)
        os.makedirs(path, exist_ok=True)
        probe = os.path.join(path, ".backup_write_test")
        with open(probe, "w", encoding="utf-8") as f:
            f.write("ok")
        os.remove(probe)
        set_setting("automatic_backup_dir", path)
        flash(f"Automatic backup location saved: {path}", "success")
    except Exception as e:
        flash(f"Native folder chooser is available when the web server runs on a desktop. {e}", "error")
    return redirect(url_for("backup_page"))

@app.route("/backup/schedule", methods=["POST"])
@login_required
@admin_required
def backup_schedule():
    value = (request.form.get("backup_time") or "19:00").strip()
    try:
        h, m = map(int, value.split(":"))
        if not (0 <= h <= 23 and 0 <= m <= 59):
            raise ValueError
    except Exception:
        flash("Please enter a valid backup time in HH:MM format.", "error")
        return redirect(url_for("backup_page"))
    set_setting("automatic_backup_time", f"{h:02d}:{m:02d}")
    flash(f"Automatic backup time set to {h:02d}:{m:02d}.", "success")
    return redirect(url_for("backup_page"))

@app.route("/backup/test", methods=["POST"])
@login_required
@admin_required
def backup_test():
    ok, msg = _run_automatic_backup()
    flash(("Test backup successful. " if ok else "Test backup failed. ") + msg, "success" if ok else "error")
    return redirect(url_for("backup_page"))

@app.route("/backup/google/connect")
@login_required
@admin_required
def google_connect():
    import google_drive as gdrive

    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

    redirect_uri = (
        os.environ.get("GOOGLE_REDIRECT_URI", "").strip()
        or url_for("google_callback", _external=True)
    )

    result, err = gdrive.get_auth_url(redirect_uri)

    if err:
        flash(err, "error")
        return redirect(url_for("backup_page"))

    # Keep verifier in session AND on disk.
    session["gdrive_oauth_state"] = result.get("state")
    session["gdrive_code_verifier"] = result.get("code_verifier")
    session.modified = True

    return redirect(result["url"])
    import google_drive as gdrive
    # Local testing allows http://
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
    redirect_uri = url_for("google_callback", _external=True)
    result, err = gdrive.get_auth_url(redirect_uri)
    if err:
        flash(err, "error")
        return redirect(url_for("backup_page"))
    # Keep verifier in session AND on disk (disk survives cookie issues)
    session["gdrive_oauth_state"] = result.get("state")
    session["gdrive_code_verifier"] = result.get("code_verifier")
    session.modified = True
    return redirect(result["url"])


@app.route("/backup/google/callback")
@login_required
@admin_required
def google_callback():
    import google_drive as gdrive

    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

    redirect_uri = (
        os.environ.get("GOOGLE_REDIRECT_URI", "").strip()
        or url_for("google_callback", _external=True)
    )

    code_verifier = session.pop(
        "gdrive_code_verifier",
        None
    )

    state = (
        request.args.get("state")
        or session.pop("gdrive_oauth_state", None)
    )

    ok, msg = gdrive.finish_auth(
        redirect_uri,
        request.url,
        code_verifier=code_verifier,
        state=state,
    )

    flash(
        msg,
        "success" if ok else "error"
    )

    return redirect(url_for("backup_page"))
    import google_drive as gdrive
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
    redirect_uri = url_for("google_callback", _external=True)
    code_verifier = session.pop("gdrive_code_verifier", None)
    state = request.args.get("state") or session.pop("gdrive_oauth_state", None)
    ok, msg = gdrive.finish_auth(
        redirect_uri,
        request.url,
        code_verifier=code_verifier,
        state=state,
    )
    flash(msg, "success" if ok else "error")
    return redirect(url_for("backup_page"))


@app.route("/backup/google/upload", methods=["POST"])
@login_required
@admin_required
def google_upload():
    import google_drive as gdrive
    import os as _os
    if not _os.path.isfile(DB_FILE):
        flash("Database file not found", "error")
        return redirect(url_for("backup_page"))
    ok, msg = gdrive.upload_file(DB_FILE)
    flash(msg, "success" if ok else "error")
    if ok:
        log_audit(
            session["doctor_id"],
            session.get("doctor_name", ""),
            "backup",
            entity="drive",
            detail=msg,
        )
    return redirect(url_for("backup_page"))


@app.route("/backup/google/disconnect", methods=["POST"])
@login_required
@admin_required
def google_disconnect():
    import google_drive as gdrive
    ok, msg = gdrive.disconnect()
    flash(msg, "info" if ok else "error")
    return redirect(url_for("backup_page"))


@app.route("/backup/download")
@login_required
def backup_download():
    """Create a consistent SQLite snapshot and download it to the doctor's device."""
    import sqlite3
    import tempfile
    from flask import send_file, after_this_request

    if not os.path.isfile(DB_FILE):
        flash("Database file not found.", "error")
        return redirect(url_for("backup_page"))

    fd, snapshot = tempfile.mkstemp(prefix="holy_bethel_backup_", suffix=".db")
    os.close(fd)
    try:
        source = sqlite3.connect(DB_FILE, timeout=30)
        target = sqlite3.connect(snapshot)
        with target:
            source.backup(target)
        target.close()
        source.close()
        log_audit(
            session["doctor_id"],
            session.get("doctor_name", ""),
            "backup",
            entity="database",
            detail="Downloaded a consistent local SQLite backup.",
        )
        response = send_file(
            snapshot,
            as_attachment=True,
            download_name=f"holy_bethel_clinic_backup_{datetime.now():%Y%m%d_%H%M%S}.db",
            mimetype="application/x-sqlite3",
        )

        @after_this_request
        def cleanup(response):
            try:
                os.remove(snapshot)
            except OSError:
                pass
            return response

        return response
    except Exception as e:
        if os.path.isfile(snapshot):
            os.remove(snapshot)
        flash(f"Backup could not be created: {e}", "error")
        return redirect(url_for("backup_page"))


@app.route("/backup/restore-db", methods=["POST"])
@login_required
@admin_required
def backup_restore_db():
    """Restore either a SQLite backup or a PostgreSQL SQL dump."""
    import sqlite3
    import shutil
    import tempfile
    import subprocess

    f = request.files.get("dbfile")

    if not f or not f.filename:
        flash("Choose a backup file.", "error")
        return redirect(url_for("backup_page"))

    filename = f.filename.lower()

    # ============================================================
    # SQLITE — LOCAL DESKTOP VERSION
    # ============================================================
    if DB_BACKEND == "sqlite":
        if not filename.endswith((".db", ".sqlite", ".sqlite3")):
            flash(
                "File must be a .db, .sqlite, or .sqlite3 backup.",
                "error",
            )
            return redirect(url_for("backup_page"))

        tmp_path = DB_FILE + ".upload_tmp"

        try:
            f.save(tmp_path)

            # Validate that the uploaded file is really a clinic
            # SQLite database.
            test_conn = sqlite3.connect(tmp_path)
            try:
                tables = {
                    row[0]
                    for row in test_conn.execute(
                        "SELECT name FROM sqlite_master "
                        "WHERE type='table'"
                    ).fetchall()
                }
            finally:
                test_conn.close()

            if "patients" not in tables or "doctors" not in tables:
                raise RuntimeError(
                    "That file doesn't look like a clinic backup "
                    "(missing patients/doctors tables)."
                )

            # Keep a safety copy of the current database.
            if os.path.isfile(DB_FILE):
                safety_name = (
                    DB_FILE
                    + f".before_restore_{datetime.now():%Y%m%d_%H%M%S}"
                )
                shutil.copy2(DB_FILE, safety_name)

            # Replace the current database only after validation succeeds.
            shutil.move(tmp_path, DB_FILE)

            log_audit(
                session.get("doctor_id"),
                session.get("doctor_name", ""),
                "restore",
                entity="database",
                detail=f"Restored from uploaded file {f.filename}",
            )

            flash(
                "Database restored. A safety copy of the previous database "
                "was kept. Please log out and log back in with the credentials "
                "from the restored backup.",
                "success",
            )

            session.clear()
            return redirect(url_for("login"))

        except Exception as e:
            if os.path.isfile(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass

            flash(f"Database restore failed: {e}", "error")
            return redirect(url_for("backup_page"))

    # ============================================================
    # POSTGRESQL — RENDER / NEON VERSION
    # ============================================================
    if DB_BACKEND == "postgresql":
        if not filename.endswith(".sql"):
            flash(
                "For the online application, choose a PostgreSQL .sql backup.",
                "error",
            )
            return redirect(url_for("backup_page"))

        if not DATABASE_URL:
            flash(
                "PostgreSQL database connection is not configured.",
                "error",
            )
            return redirect(url_for("backup_page"))

        tmp_path = None
        safety_path = None

        try:
            # ----------------------------------------------------
            # 1. Save uploaded SQL backup.
            # ----------------------------------------------------
            fd, tmp_path = tempfile.mkstemp(
                prefix="clinic_restore_",
                suffix=".sql",
            )
            os.close(fd)
            f.save(tmp_path)

            # ----------------------------------------------------
            # 2. Create safety backup of current PostgreSQL DB.
            # ----------------------------------------------------
            fd, safety_path = tempfile.mkstemp(
                prefix="clinic_before_restore_",
                suffix=".sql",
            )
            os.close(fd)

            safety_result = subprocess.run(
                [
                    "pg_dump",
                    DATABASE_URL,
                    "--no-owner",
                    "--no-privileges",
                    "-f",
                    safety_path,
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )

            if safety_result.returncode != 0:
                raise RuntimeError(
                    safety_result.stderr.strip()
                    or "Could not create a safety backup before restore."
                )

            # ----------------------------------------------------
            # 3. Read uploaded SQL.
            # ----------------------------------------------------
            with open(
                tmp_path,
                "r",
                encoding="utf-8",
                errors="replace",
            ) as source:
                uploaded_sql = source.read()

            if not uploaded_sql.strip():
                raise RuntimeError("The uploaded SQL backup is empty.")

            # ----------------------------------------------------
            # 4. Restore inside one PostgreSQL transaction.
            # ----------------------------------------------------
            restore_script = (
                "BEGIN;\n\n"
                "DROP TABLE IF EXISTS telegram_outbox CASCADE;\n"
                "DROP TABLE IF EXISTS audit_log CASCADE;\n"
                "DROP TABLE IF EXISTS settings CASCADE;\n"
                "DROP TABLE IF EXISTS patients CASCADE;\n"
                "DROP TABLE IF EXISTS doctors CASCADE;\n\n"
                + uploaded_sql
                + "\n\nCOMMIT;\n"
            )

            with open(
                tmp_path,
                "w",
                encoding="utf-8",
            ) as target:
                target.write(restore_script)

            # ----------------------------------------------------
            # 5. Execute restore.
            # ----------------------------------------------------
            restore_result = subprocess.run(
                [
                    "psql",
                    DATABASE_URL,
                    "--set",
                    "ON_ERROR_STOP=1",
                    "-f",
                    tmp_path,
                ],
                capture_output=True,
                text=True,
                timeout=180,
            )

            if restore_result.returncode != 0:
                raise RuntimeError(
                    restore_result.stderr.strip()
                    or "PostgreSQL restore failed."
                )

            # ----------------------------------------------------
            # 6. Re-run migrations/default settings.
            # ----------------------------------------------------
            init_db()

            # ----------------------------------------------------
            # 7. Verify required application tables.
            # ----------------------------------------------------
            with get_conn() as verify_conn:
                required_tables = {
                    "patients",
                    "doctors",
                    "settings",
                    "audit_log",
                    "telegram_outbox",
                }

                placeholders = ", ".join(
                    ["%s"] * len(required_tables)
                )

                verify_cursor = verify_conn.execute(
                    f"""
                    SELECT table_name
                    FROM information_schema.tables
                    WHERE table_schema = 'public'
                      AND table_name IN ({placeholders})
                    """,
                    tuple(required_tables),
                )

                found_tables = {
                    row["table_name"]
                    for row in verify_cursor.fetchall()
                }

            missing_tables = required_tables - found_tables

            if missing_tables:
                raise RuntimeError(
                    "Restore completed but the required clinic tables "
                    "are missing: "
                    + ", ".join(sorted(missing_tables))
                )

            # ----------------------------------------------------
            # 8. Restore succeeded.
            # ----------------------------------------------------
            log_audit(
                None,
                "System",
                "restore",
                entity="database",
                detail=f"Restored PostgreSQL database from {f.filename}",
            )

            flash(
                "PostgreSQL database restored successfully. "
                "The restored schema was verified and a safety backup "
                "of the previous database was created before the restore.",
                "success",
            )

            session.clear()
            return redirect(url_for("login"))

        except FileNotFoundError as e:
            command = str(e.filename or "pg_dump/psql")

            flash(
                f"PostgreSQL restore requires '{command}', "
                "but it is not available on the server.",
                "error",
            )
            return redirect(url_for("backup_page"))

        except Exception as e:
            flash(
                f"PostgreSQL database restore failed: {e}",
                "error",
            )
            return redirect(url_for("backup_page"))

        finally:
            if tmp_path and os.path.isfile(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass

            # The safety backup is intentionally retained.

    flash("Unknown database backend.", "error")
    return redirect(url_for("backup_page"))


@app.route("/backup/import-csv", methods=["POST"])
@login_required
def backup_import_csv():
    doctor_id = session["doctor_id"]
    f = request.files.get("file")
    if not f or not f.filename:
        flash("Choose a CSV file", "error")
        return redirect(url_for("backup_page"))
    try:
        text = f.read().decode("utf-8-sig")
        reader = csv.DictReader(io.StringIO(text))
        n = 0
        with get_conn() as conn:
            for row in reader:
                # Flexible headers from desktop or web export
                keys = { (k or "").strip().lower(): v for k, v in row.items() }
                def pick(*names):
                    for name in names:
                        if name in keys and keys[name] not in (None, ""):
                            return keys[name]
                    return ""
                greg = pick("gregorian", "greg_date", "date") or datetime.now().strftime("%Y-%m-%d")
                eth = pick("ethiopian", "eth_date") or get_ethiopian_date(greg)
                patient = (pick("patient", "patient_name", "name") or "").strip().title()
                ticket = (pick("ticket", "ticket_no") or "").strip().upper()
                procedure = (pick("procedure") or "").strip().title()
                try:
                    fee = float(pick("fee", "total_fee", "price") or 0)
                except ValueError:
                    fee = 0
                try:
                    pct = float(pick("pct", "doctor_pct", "cut %") or 4)
                except ValueError:
                    pct = 4.0
                if not patient:
                    continue
                cut = fee * (pct / 100.0)
                _execute(conn,
                    """INSERT INTO patients
                       (greg_date, eth_date, patient_name, ticket_no, procedure,
                        total_fee, doctor_pct, my_earning, doctor_id)
                       VALUES (?,?,?,?,?,?,?,?,?)""",
                    (greg, eth, patient, ticket, procedure, fee, pct, cut, doctor_id),
                )
                n += 1
        log_audit(doctor_id, session.get("doctor_name", ""), "import", detail=f"{n} rows from CSV")
        flash(f"Imported {n} patient record(s)", "success")
    except Exception as e:
        flash(f"Import failed: {e}", "error")
    return redirect(url_for("backup_page"))


@app.route("/monthly/report.html")
@login_required
def monthly_report_html():
    doctor_id = session["doctor_id"]
    eth = get_ethiopian_date()
    parts = eth.split()
    m, y = (parts[0], parts[2]) if len(parts) >= 3 else ("", "")
    with get_conn() as conn:
        rows = _execute(conn,
            "SELECT * FROM patients WHERE doctor_id=? ORDER BY id", (doctor_id,)
        ).fetchall()
        doc = _execute(conn,
            "SELECT name, base_salary FROM doctors WHERE id=?", (doctor_id,)
        ).fetchone()
    month_rows = [
        r for r in rows
        if r["eth_date"] and m in r["eth_date"] and y in r["eth_date"]
    ]
    income = sum(float(r["total_fee"] or 0) for r in month_rows)
    cut = sum(float(r["my_earning"] or 0) for r in month_rows)
    base = float(doc["base_salary"] if doc else 45000)
    take = base + cut
    rows_html = "".join(
        f"<tr><td>{r['eth_date']}</td><td>{r['patient_name']}</td>"
        f"<td>{r['ticket_no'] or ''}</td><td>{r['procedure']}</td>"
        f"<td>{float(r['total_fee'] or 0):,.2f}</td>"
        f"<td>{float(r['my_earning'] or 0):,.2f}</td></tr>"
        for r in month_rows
    )
    html = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Monthly - {m} {y}</title>
<style>
body{{font-family:Segoe UI,sans-serif;background:#f1f1ef;padding:24px;color:#1a1a1a}}
.card{{max-width:900px;margin:auto;background:#fff;padding:28px;border-radius:14px;border:1px solid #e1e1df}}
h1{{color:#55616c;border-bottom:3px solid #b98a3e;padding-bottom:12px}}
.stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:16px 0}}
.stat{{background:#f7f7f5;border:1px solid #e1e1df;border-radius:10px;padding:12px}}
.stat b{{display:block;font-size:1.15rem;margin-top:4px}}
table{{width:100%;border-collapse:collapse;margin-top:12px}}
th{{background:#55616c;color:#fff;text-align:left;padding:8px}}
td{{padding:8px;border-bottom:1px solid #e1e1df}}
.banner{{background:linear-gradient(135deg,#b98a3e,#9c7433);color:#fff;padding:16px;border-radius:12px;text-align:center;margin-top:16px}}
@media print{{.noprint{{display:none}}}}
</style></head><body><div class="card">
<h1>Dental {CLINIC_NAME}</h1>
<p>Monthly report - {m} {y} - {doc['name'] if doc else ''}</p>
<div class="stats">
<div class="stat">Patients<b>{len(month_rows)}</b></div>
<div class="stat">Income<b>{income:,.2f} ETB</b></div>
<div class="stat">Doctor cut<b>{cut:,.2f} ETB</b></div>
<div class="stat">Base salary<b>{base:,.2f} ETB</b></div>
</div>
<div class="banner"><div>Take-home</div><strong style="font-size:1.5rem">{take:,.2f} ETB</strong></div>
<table><thead><tr><th>Eth date</th><th>Patient</th><th>Ticket</th><th>Procedure</th><th>Fee</th><th>Cut</th></tr></thead>
<tbody>{rows_html or '<tr><td colspan="6">No records</td></tr>'}</tbody></table>
<p class="noprint" style="text-align:center;margin-top:20px"><button onclick="window.print()">Print / Save PDF</button></p>
</div></body></html>"""
    return Response(html, mimetype="text/html")


@app.route("/audit")
@login_required
@admin_required
def audit():
    with get_conn() as conn:
        rows = _execute(conn,
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT 200"
        ).fetchall()
    return render_template("audit.html", rows=rows)


# ---------------------------------------------------------------------------
# Background scheduler (runs while the web process is alive â€” 24/7 on a server)
# ---------------------------------------------------------------------------
def _process_outbox():
    for row in pending_outbox():
        ok, detail = try_send_for_doctor(row["doctor_id"], row["message_text"])
        if ok:
            mark_outbox_sent(row["id"])
        else:
            mark_outbox_fail(row["id"], int(row["attempts"] or 0) + 1, detail)


def _scheduled_daily():
    today = datetime.now().strftime("%Y-%m-%d")
    with get_conn() as conn:
        docs = _execute(conn,
            "SELECT id FROM doctors WHERE telegram_enabled=1 AND telegram_bot_token!='' AND telegram_chat_id!=''"
        ).fetchall()
        for d in docs:
            text = build_daily_report(d["id"], today)
            ok, detail = try_send_for_doctor(d["id"], text)
            if not ok:
                queue_telegram(d["id"], text)


def _scheduled_monthly():
    today = datetime.now().strftime("%Y-%m-%d")
    if not is_ethiopian_month_end(today):
        return
    if not build_monthly_report:
        return
    with get_conn() as conn:
        docs = _execute(conn,
            "SELECT id FROM doctors WHERE telegram_enabled=1 AND telegram_bot_token!='' AND telegram_chat_id!=''"
        ).fetchall()
    for d in docs:
        text, _label = build_monthly_report(d["id"])
        if not text:
            continue
        ok, _ = try_send_for_doctor(d["id"], text)
        if not ok:
            queue_telegram(d["id"], text)


def start_scheduler():
    """
    Start background tasks that belong to the Flask application.

    Scheduled backup and Telegram reports are handled by Render Cron Jobs.
    This prevents duplicate execution between the web service and Render.
    """
    sched = BackgroundScheduler(daemon=True)

    sched.add_job(
        _process_outbox,
        "interval",
        minutes=2,
        id="outbox",
        replace_existing=True
    )

    sched.start()
    return sched




