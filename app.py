"""
Holy Bethel Dental Clinic — Web application
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

from config import SECRET_KEY, CLINIC_NAME, CLINIC_NAME_SHORT, DAILY_REPORT_TIME, MONTHLY_REPORT_TIME
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
    reset_password_with_token,
)
from config import DB_FILE, DATA_DIR
from ethiopian import get_ethiopian_date, is_ethiopian_month_end, ETH_MONTHS
from telegram_util import (
    build_daily_report,
    build_earning_message,
    try_send_for_doctor,
)

# Optional newer telegram helpers (monthly / delete) if present
try:
    from telegram_util import build_monthly_report, build_delete_message
except ImportError:
    build_monthly_report = None
    build_delete_message = None

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
        today_cut = conn.execute(
            "SELECT COALESCE(SUM(my_earning),0) AS s FROM patients WHERE doctor_id=? AND greg_date=?",
            (doctor_id, today),
        ).fetchone()["s"]
        all_rows = conn.execute(
            "SELECT greg_date, eth_date, total_fee, my_earning FROM patients WHERE doctor_id=?",
            (doctor_id,),
        ).fetchall()
        recent = conn.execute(
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
        rows = conn.execute(
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
            cur = conn.execute(
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
            detail=f"{patient} · {procedure} · {fee:,.2f}",
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
        flash(f"Saved {patient}" + (" · Telegram sent" if ok else " · Telegram queued"), "success")
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
        row = conn.execute(
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
            conn.execute(
                """UPDATE patients SET greg_date=?, eth_date=?, patient_name=?, ticket_no=?,
                   procedure=?, total_fee=?, doctor_pct=?, my_earning=?
                   WHERE id=? AND doctor_id=?""",
                (greg, eth, patient, ticket, procedure, fee, pct, cut, pid, doctor_id),
            )
        log_audit(
            doctor_id, session.get("doctor_name", ""), "update",
            entity_id=pid, detail=f"{patient} · {procedure} · {fee:,.2f}",
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
        row = conn.execute(
            "SELECT * FROM patients WHERE id=? AND doctor_id=?",
            (pid, doctor_id),
        ).fetchone()
        if row:
            name = row["patient_name"]
            conn.execute("DELETE FROM patients WHERE id=?", (pid,))
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
        rows = conn.execute(
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
    resp = make_response(buf.getvalue())
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
        r = conn.execute(
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
<h2>🦷 {CLINIC_NAME}</h2>
<p>Treatment Receipt · {session.get('doctor_name','')}</p>
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
        rows = conn.execute(
            "SELECT eth_date, total_fee, my_earning FROM patients WHERE doctor_id=?",
            (doctor_id,),
        ).fetchall()
        doc = conn.execute(
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
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        try:
            info = create_password_reset_token(username)
            # Do not reveal whether the username/email exists.
            if info:
                _send_password_reset_email(info["email"], info["name"], info["token"])
            flash("If an account with that username has a recovery email, a reset link has been sent.", "success")
            return redirect(url_for("login"))
        except Exception as e:
            # Avoid leaking account existence while still surfacing mail configuration problems.
            flash(str(e), "error")
    return render_template("forgot.html")


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
    msg["Subject"] = f"{CLINIC_NAME} — password reset"
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
            conn.execute(
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
    """Create a consistent SQLite backup in the configured automatic-backup folder."""
    import sqlite3
    backup_dir = _get_backup_dir()
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    target_path = os.path.join(backup_dir, f"holy_bethel_backup_{stamp}.db")
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
    if not os.path.isfile(DB_FILE):
        return False, "Database file not found."
    try:
        path = _create_backup_snapshot()
        local_removed = _cleanup_local_backups()
        drive_ok = False
        drive_msg = "Google Drive not connected."
        try:
            import google_drive as gdrive
            if gdrive.is_connected():
                drive_ok, drive_msg = gdrive.upload_file(path)
                _cleanup_google_backups()
        except Exception as e:
            drive_msg = str(e)
        return True, f"Backup created: {os.path.basename(path)}. Local old backups removed: {local_removed}. {drive_msg}"
    except Exception as e:
        return False, f"Automatic backup failed: {e}"


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
    if _scheduler is not None:
        try:
            _scheduler.reschedule_job("automatic_backup", trigger="cron", hour=h, minute=m)
        except Exception:
            pass
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
    import sqlite3
    import shutil
    f = request.files.get("dbfile")
    if not f or not f.filename:
        flash("Choose a .db file", "error")
        return redirect(url_for("backup_page"))
    if not f.filename.lower().endswith((".db", ".sqlite", ".sqlite3")):
        flash("File must be a .db / .sqlite backup", "error")
        return redirect(url_for("backup_page"))

    tmp_path = DB_FILE + ".upload_tmp"
    f.save(tmp_path)

    # Validate it's really a SQLite database with a doctors/patients table
    try:
        test_conn = sqlite3.connect(tmp_path)
        tables = {
            row[0]
            for row in test_conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        test_conn.close()
        if "patients" not in tables or "doctors" not in tables:
            os.remove(tmp_path)
            flash(
                "That file doesn't look like a clinic backup "
                "(missing patients/doctors tables).",
                "error",
            )
            return redirect(url_for("backup_page"))
    except Exception as e:
        if os.path.isfile(tmp_path):
            os.remove(tmp_path)
        flash(f"Invalid database file: {e}", "error")
        return redirect(url_for("backup_page"))

    # Safety copy of the current (about-to-be-replaced) database
    if os.path.isfile(DB_FILE):
        safety_name = DB_FILE + f".before_restore_{datetime.now():%Y%m%d_%H%M%S}"
        shutil.copy2(DB_FILE, safety_name)

    shutil.move(tmp_path, DB_FILE)

    log_audit(
        session.get("doctor_id"),
        session.get("doctor_name", ""),
        "restore",
        entity="database",
        detail=f"Restored from uploaded file {f.filename}",
    )
    flash(
        "Database restored. A safety copy of the previous database was kept on the server. "
        "Please log out and log back in with the credentials from the restored backup.",
        "success",
    )
    session.clear()
    return redirect(url_for("login"))


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
                conn.execute(
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
        rows = conn.execute(
            "SELECT * FROM patients WHERE doctor_id=? ORDER BY id", (doctor_id,)
        ).fetchall()
        doc = conn.execute(
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
<title>Monthly · {m} {y}</title>
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
<h1>🦷 {CLINIC_NAME}</h1>
<p>Monthly report · {m} {y} · {doc['name'] if doc else ''}</p>
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
        rows = conn.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT 200"
        ).fetchall()
    return render_template("audit.html", rows=rows)


# ---------------------------------------------------------------------------
# Background scheduler (runs while the web process is alive — 24/7 on a server)
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
        docs = conn.execute(
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
        docs = conn.execute(
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
    sched = BackgroundScheduler(daemon=True)
    sched.add_job(_process_outbox, "interval", minutes=2, id="outbox")
    daily = get_setting("telegram_daily_report_time", DAILY_REPORT_TIME) or DAILY_REPORT_TIME
    monthly = get_setting("telegram_monthly_report_time", MONTHLY_REPORT_TIME) or MONTHLY_REPORT_TIME
    backup_time = get_setting("automatic_backup_time", "19:00") or "19:00"
    try:
        bh, bmi = map(int, backup_time.split(":"))
        sched.add_job(_run_automatic_backup, "cron", hour=bh, minute=bmi, id="automatic_backup", replace_existing=True)
    except Exception:
        sched.add_job(_run_automatic_backup, "cron", hour=19, minute=0, id="automatic_backup", replace_existing=True)
    try:
        h, mi = map(int, daily.split(":"))
        sched.add_job(_scheduled_daily, "cron", hour=h, minute=mi, id="daily")
    except Exception:
        sched.add_job(_scheduled_daily, "cron", hour=19, minute=0, id="daily")
    try:
        h, mi = map(int, monthly.split(":"))
        sched.add_job(_scheduled_monthly, "cron", hour=h, minute=mi, id="monthly")
    except Exception:
        pass
    sched.start()
    return sched


_scheduler = None


# Scheduler is intentionally not started from Flask requests.
# Run scheduler.py as a separate process in production to avoid duplicate jobs with multiple web workers.


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
