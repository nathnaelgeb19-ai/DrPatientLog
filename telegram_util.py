"""Telegram HTTP helpers and branded reports."""
import json
import ssl
import urllib.request
from html import escape as html_escape
from datetime import datetime

from config import CLINIC_NAME, CLINIC_NAME_SHORT
from ethiopian import get_ethiopian_date
from db import get_conn, get_doctor

try:
    import certifi
    _SSL = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    _SSL = ssl.create_default_context()


def _rule():
    return "─" * 22


def _header(emoji, title, subtitle=None):
    lines = [
        f"{emoji} <b>{html_escape(CLINIC_NAME)}</b>",
        f"<b>{html_escape(title)}</b>",
    ]
    if subtitle:
        lines[1] = f"<b>{html_escape(title)}</b> · {html_escape(str(subtitle))}"
    lines.append(_rule())
    return "\n".join(lines)


def _footer():
    return f"{_rule()}\n{html_escape(CLINIC_NAME_SHORT)}"


def send_telegram(token, chat_id, text, timeout=20):
    try:
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = json.dumps({
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }).encode("utf-8")
        req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        if body.get("ok"):
            return True, "ok"
        return False, str(body.get("description") or "rejected")
    except Exception as e:
        return False, str(e)


def send_telegram_document(token, chat_id, file_path, caption="", timeout=60):
    """Send a file/document to a Telegram chat using the Bot API."""
    import mimetypes
    import os
    import uuid

    try:
        if not token or not chat_id:
            return False, "missing Telegram credentials"

        if not file_path or not os.path.isfile(file_path):
            return False, "backup file not found"

        boundary = "----DrPatientLogBoundary" + uuid.uuid4().hex
        filename = os.path.basename(file_path)

        mime_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"

        fields = [
            (
                "--" + boundary + "\r\n"
                'Content-Disposition: form-data; name="chat_id"\r\n\r\n'
                + str(chat_id)
                + "\r\n"
            )
        ]

        if caption:
            fields.append(
                "--" + boundary + "\r\n"
                'Content-Disposition: form-data; name="caption"\r\n\r\n'
                + str(caption)
                + "\r\n"
            )

        body = "".join(fields).encode("utf-8")

        with open(file_path, "rb") as f:
            file_data = f.read()

        body += (
            ("--" + boundary + "\r\n").encode("utf-8")
            + (
                'Content-Disposition: form-data; name="document"; '
                'filename="' + filename.replace('"', "") + '"\r\n'
            ).encode("utf-8")
            + ("Content-Type: " + mime_type + "\r\n\r\n").encode("utf-8")
            + file_data
            + b"\r\n"
            + ("--" + boundary + "--\r\n").encode("utf-8")
        )

        url = f"https://api.telegram.org/bot{token}/sendDocument"

        req = urllib.request.Request(
            url,
            data=body,
            headers={
                "Content-Type": f"multipart/form-data; boundary={boundary}",
            },
            method="POST",
        )

        with urllib.request.urlopen(req, timeout=timeout, context=_SSL) as resp:
            response_body = json.loads(resp.read().decode("utf-8"))

        if response_body.get("ok"):
            return True, "ok"

        return False, str(
            response_body.get("description") or "Telegram rejected the document"
        )

    except Exception as e:
        return False, str(e)

def try_send_for_doctor(doctor_id, text):
    doc = get_doctor(doctor_id)
    if not doc:
        return False, "no doctor"
    if not doc.get("telegram_enabled"):
        return False, "disabled"
    token = (doc.get("telegram_bot_token") or "").strip()
    chat = (doc.get("telegram_chat_id") or "").strip()
    if not token or not chat:
        return False, "missing credentials"
    return send_telegram(token, chat, text)


def _month_totals(doctor_id, eth_date_str):
    parts = (eth_date_str or "").split()
    eth_m = parts[0] if parts else ""
    eth_y = parts[2] if len(parts) >= 3 else ""
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT eth_date, total_fee, my_earning FROM patients WHERE doctor_id=?",
            (doctor_id,),
        ).fetchall()
        doc = conn.execute("SELECT base_salary FROM doctors WHERE id=?", (doctor_id,)).fetchone()
    income = cut_sum = 0.0
    for r in rows:
        if r["eth_date"] and eth_m in r["eth_date"] and eth_y in r["eth_date"]:
            income += float(r["total_fee"] or 0)
            cut_sum += float(r["my_earning"] or 0)
    base = float(doc["base_salary"] if doc else 45000)
    return f"{eth_m} {eth_y}".strip(), income, cut_sum, base, base + cut_sum


def build_daily_report(doctor_id, greg_date_str=None):
    dt = datetime.strptime(greg_date_str, "%Y-%m-%d") if greg_date_str else datetime.now()
    greg = dt.strftime("%Y-%m-%d")
    eth = get_ethiopian_date(greg)
    with get_conn() as conn:
        rows = conn.execute(
            """SELECT patient_name, ticket_no, procedure, total_fee, my_earning
               FROM patients WHERE doctor_id=? AND greg_date=? ORDER BY id""",
            (doctor_id, greg),
        ).fetchall()
    total_income = sum(float(r["total_fee"] or 0) for r in rows)
    total_cut = sum(float(r["my_earning"] or 0) for r in rows)
    report = (
        f"{_header('🦷', 'Daily report')}\n"
        f"📅 Gregorian: {html_escape(greg)}\n"
        f"📅 Ethiopian: {html_escape(eth or '—')}\n"
        f"👥 Patients: <b>{len(rows)}</b>\n"
        f"💰 Total income: <b>{total_income:,.2f} Birr</b>\n"
        f"✂️ Doctor cut: <b>{total_cut:,.2f} Birr</b>"
    )
    if rows:
        report += f"\n\n📋 <b>Today's records</b> · {min(len(rows), 25)} of {len(rows)}"
        for i, r in enumerate(rows[:25], 1):
            t = f" · #{html_escape(str(r['ticket_no']))}" if r["ticket_no"] else ""
            report += (
                f"\n{i}. <b>{html_escape(str(r['patient_name'] or '—'))}</b>{t}"
                f"\n   {html_escape(str(r['procedure'] or '—'))}"
                f" · {float(r['total_fee'] or 0):,.2f} Birr"
            )
    else:
        report += "\n\n• No patient records registered today."
    return report + f"\n{_footer()}"


def build_monthly_report(doctor_id, eth_date_str=None):
    eth_date_str = eth_date_str or get_ethiopian_date()
    parts = (eth_date_str or '').split()
    if len(parts) < 3:
        return '', ''
    eth_m, eth_y = parts[0], parts[2]
    month_label = f'{eth_m} {eth_y}'
    with get_conn() as conn:
        rows = conn.execute('SELECT patient_name, ticket_no, procedure, eth_date, total_fee, my_earning FROM patients WHERE doctor_id=? ORDER BY id', (doctor_id,)).fetchall()
        doc = conn.execute('SELECT base_salary FROM doctors WHERE id=?', (doctor_id,)).fetchone()
    month_rows = [r for r in rows if r['eth_date'] and eth_m in r['eth_date'] and eth_y in r['eth_date']]
    income = sum(float(r['total_fee'] or 0) for r in month_rows)
    cut = sum(float(r['my_earning'] or 0) for r in month_rows)
    base = float(doc['base_salary'] if doc else 45000)
    take = base + cut
    report = (f'{_header("MONTHLY", "Monthly report", month_label)}\n'
              f'Patients treated: <b>{len(month_rows)}</b>\n'
              f'Total income: <b>{income:,.2f} Birr</b>\n'
              f'Your cut: <b>{cut:,.2f} Birr</b>\n'
              f'Base salary: {base:,.2f} Birr\n'
              f'<b>Take-home: {take:,.2f} Birr</b>')
    if month_rows:
        report += f'\n\n<b>Patient records</b> - {min(len(month_rows), 25)} of {len(month_rows)}'
        for i, r in enumerate(month_rows[:25], 1):
            report += (f'\n{i}. {html_escape(str(r["eth_date"] or "-"))}'
                       f' - <b>{html_escape(str(r["patient_name"] or "-"))}</b>'
                       f'\n   {html_escape(str(r["procedure"] or "-"))}'
                       f' - {float(r["total_fee"] or 0):,.2f} Birr')
    return report + f'\n{_footer()}', month_label
def build_earning_message(title, eth, ticket, patient, procedure, fee, cut, doctor_id):
    label, income, cut_sum, base, take = _month_totals(doctor_id, eth)
    return (
        f"{_header('EARNING', title)}\n"
        f"Date: {html_escape(str(eth or '-'))}\n"
        f"Ticket: <b>{html_escape(str(ticket or '-'))}</b>\n"
        f"Patient: <b>{html_escape(str(patient or '-'))}</b>\n"
        f"Procedure: {html_escape(str(procedure or '-'))}\n"
        f"Fee: <b>{fee:,.2f} Birr</b>\n"
        f"Your cut: <b>{cut:,.2f} Birr</b>\n\n"
        f"Month to date - <b>{html_escape(label)}</b>\n"
        f"- Income: {income:,.2f} Birr\n"
        f"- Your cut: {cut_sum:,.2f} Birr\n"
        f"- Base salary: {base:,.2f} Birr\n"
        f"Take-home: <b>{take:,.2f} Birr</b>\n"
        f"{_footer()}"
    )


def build_delete_message(names, count=1):
    if count <= 1:
        block = f"Patient: <b>{html_escape(str(names))}</b>"
        title = "Record deleted"
    else:
        block = f"Patients ({count}):\n" + "\n".join(
            f"- {html_escape(str(n))}" for n in names
        )
        title = f"{count} records deleted"

    return (
        f"{_header('DELETE', title)}\n"
        f"{block}\n\n"
        f"Removed from the clinic database.\n"
        f"{_footer()}"
    )
