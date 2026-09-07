"""Ethiopian calendar helpers (ported from desktop app)."""
from datetime import datetime, timedelta

ETH_MONTHS = [
    "መስከረም",
    "ጥቅምት",
    "ህዳር",
    "ታኅሣሥ",
    "ጥር",
    "የካቲት",
    "መጋቢት",
    "ሚያዝያ",
    "ግንቦት",
    "ሰኔ",
    "ሐምሌ",
    "ነሐሴ",
    "ጳጉሜ",
]


def get_ethiopian_date(greg_date_str=None):
    try:
        if greg_date_str:
            dt = datetime.strptime(greg_date_str.strip(), "%Y-%m-%d")
        else:
            dt = datetime.now()

        year, month, day = dt.year, dt.month, dt.day
        a = (14 - month) // 12
        y = year + 4800 - a
        m = month + 12 * a - 3
        jdn = day + (153 * m + 2) // 5 + 365 * y + y // 4 - y // 100 + y // 400 - 32045

        eth_days = jdn - 1724221
        cycles = eth_days // 1461
        rem_days = eth_days % 1461
        eth_year = cycles * 4 + 1

        if rem_days >= 365:
            if rem_days < 730:
                eth_year += 1
                rem_days -= 365
            elif rem_days < 1096:
                eth_year += 2
                rem_days -= 730
            else:
                eth_year += 3
                rem_days -= 1096

        eth_month_idx = rem_days // 30
        eth_day = (rem_days % 30) + 1
        if eth_month_idx >= 13:
            eth_month_idx = 12

        return f"{ETH_MONTHS[eth_month_idx]} {eth_day} {eth_year}"
    except Exception:
        return ""


def get_ethiopian_date_parts(greg_date_str=None):
    eth = get_ethiopian_date(greg_date_str)
    parts = (eth or "").split()
    if len(parts) >= 3:
        try:
            return parts[0], int(parts[1]), int(parts[2])
        except (TypeError, ValueError):
            pass
    return "", 0, 0


def is_ethiopian_month_end(greg_date_str=None):
    dt = datetime.strptime(greg_date_str, "%Y-%m-%d") if greg_date_str else datetime.now()
    today_month, _, today_year = get_ethiopian_date_parts(dt.strftime("%Y-%m-%d"))
    tomorrow = dt + timedelta(days=1)
    next_month, _, next_year = get_ethiopian_date_parts(tomorrow.strftime("%Y-%m-%d"))
    if not today_month or not next_month:
        return False
    return (today_month, today_year) != (next_month, next_year)
