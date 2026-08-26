import os, sqlite3, psycopg

SQLITE_DB = r"C:\Users\Nath\Downloads\Holy_Bethel_backup_20260822_190007.db"
DATABASE_URL = os.environ["MIGRATION_DATABASE_URL"]

s = sqlite3.connect(SQLITE_DB)
s.row_factory = sqlite3.Row
patients = s.execute("SELECT greg_date, eth_date, patient_name, ticket_no, procedure, total_fee, doctor_pct, my_earning, created_at FROM patients ORDER BY id").fetchall()
print(f"SQLite patients found: {len(patients)}")
if len(patients) != 14:
    raise RuntimeError(f"Expected exactly 14 patients, found {len(patients)}")

p = psycopg.connect(DATABASE_URL)
try:
    with p:
        with p.cursor() as c:
            c.execute("SET search_path TO public")
            c.execute("SELECT id, name FROM doctors WHERE id = 1")
            doctor = c.fetchone()
            if not doctor:
                raise RuntimeError("PostgreSQL doctor ID 1 does not exist.")
            print(f"Using PostgreSQL doctor: ID {doctor[0]} - {doctor[1]}")
            tickets = [row["ticket_no"] for row in patients]
            c.execute("SELECT ticket_no FROM patients WHERE ticket_no = ANY(%s)", (tickets,))
            existing = c.fetchall()
            if existing:
                raise RuntimeError(f"STOP: Matching ticket numbers already exist: {existing}")
            for row in patients:
                c.execute("INSERT INTO patients (greg_date, eth_date, patient_name, ticket_no, procedure, total_fee, doctor_pct, my_earning, doctor_id, created_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,1,%s)", (row["greg_date"], row["eth_date"], row["patient_name"], row["ticket_no"], row["procedure"], row["total_fee"], row["doctor_pct"], row["my_earning"], row["created_at"]))
            c.execute("SELECT COUNT(*) FROM patients WHERE ticket_no = ANY(%s)", (tickets,))
            count = c.fetchone()[0]
            if count != 14:
                raise RuntimeError(f"Verification failed: expected 14, found {count}")
            print("=" * 70)
            print("IMPORT SUCCESSFUL")
            print("=" * 70)
            print(f"Patients imported: {count}")
            print("Doctor ID used: 1")
            print("Other tables modified: NONE")
            print("=" * 70)
finally:
    p.close()
    s.close()
