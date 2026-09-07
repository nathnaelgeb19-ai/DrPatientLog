import os
import sqlite3
import psycopg

SQLITE_DB = r"C:\Users\Nath\Downloads\Holy_Bethel_backup_20260822_190007.db"

DATABASE_URL = os.environ.get("MIGRATION_DATABASE_URL")

if not DATABASE_URL:
    raise RuntimeError(
        "MIGRATION_DATABASE_URL is not set."
    )

# ------------------------------------------------------------
# Read the SQLite backup
# ------------------------------------------------------------

print("=" * 70)
print("DRPATIENTLOG PATIENT MIGRATION - DRY RUN")
print("=" * 70)

print("\nOpening SQLite backup...")
print(SQLITE_DB)

sqlite_conn = sqlite3.connect(SQLITE_DB)
sqlite_conn.row_factory = sqlite3.Row

patients = sqlite_conn.execute(
    """
    SELECT
        id,
        greg_date,
        eth_date,
        patient_name,
        ticket_no,
        procedure,
        total_fee,
        doctor_pct,
        my_earning,
        doctor_id,
        created_at
    FROM patients
    ORDER BY id
    """
).fetchall()

sqlite_doctor = sqlite_conn.execute(
    """
    SELECT
        id,
        name
    FROM doctors
    WHERE id = 1
    """
).fetchone()

print(f"\nSQLite patients found: {len(patients)}")

if sqlite_doctor:
    print(
        f"SQLite doctor: {sqlite_doctor['name']} "
        f"(ID {sqlite_doctor['id']})"
    )
else:
    raise RuntimeError("SQLite doctor ID 1 was not found.")

# ------------------------------------------------------------
# Connect to PostgreSQL
# ------------------------------------------------------------

print("\nConnecting to PostgreSQL...")

pg = psycopg.connect(DATABASE_URL)

try:
    with pg.cursor() as cur:

        # ----------------------------------------------------
        # Check current PostgreSQL schema
        # ----------------------------------------------------

        cur.execute(
            """
            SELECT current_database(), current_schema()
            """
        )

        db_name, schema_name = cur.fetchone()

        print(f"PostgreSQL database: {db_name}")
        print(f"PostgreSQL schema: {schema_name}")

        # Explicitly use public schema.
        cur.execute("SET search_path TO public")

        # ----------------------------------------------------
        # Check doctors
        # ----------------------------------------------------

        cur.execute(
            """
            SELECT id, name
            FROM doctors
            ORDER BY id
            """
        )

        doctors = cur.fetchall()

        print("\nCurrent PostgreSQL doctors:")

        if not doctors:
            print("  NO DOCTORS FOUND")
        else:
            for doctor_id, doctor_name in doctors:
                print(
                    f"  ID {doctor_id}: {doctor_name}"
                )

        # ----------------------------------------------------
        # Match SQLite doctor by name
        # ----------------------------------------------------

        sqlite_doctor_name = sqlite_doctor["name"].strip()

        cur.execute(
            """
            SELECT id, name
            FROM doctors
            WHERE lower(trim(name)) = lower(trim(%s))
            LIMIT 1
            """,
            (sqlite_doctor_name,),
        )

        matching_doctor = cur.fetchone()

        print("\nDoctor mapping:")

        if matching_doctor:
            pg_doctor_id, pg_doctor_name = matching_doctor

            print(
                f"  SQLite doctor: {sqlite_doctor_name}"
            )
            print(
                f"  PostgreSQL doctor: "
                f"{pg_doctor_name} (ID {pg_doctor_id})"
            )
        else:
            print(
                f"  NO MATCH FOUND for "
                f"'{sqlite_doctor_name}'"
            )
            print(
                "\nSTOP: No patient records will be imported."
            )
            raise SystemExit(1)

        # ----------------------------------------------------
        # Current PostgreSQL patient count
        # ----------------------------------------------------

        cur.execute(
            """
            SELECT COUNT(*)
            FROM patients
            """
        )

        current_patient_count = cur.fetchone()[0]

        print(
            f"\nCurrent PostgreSQL patients: "
            f"{current_patient_count}"
        )

        # ----------------------------------------------------
        # Check ticket conflicts
        # ----------------------------------------------------

        print("\nChecking ticket conflicts...")

        conflicts = []

        for patient in patients:
            ticket = patient["ticket_no"]

            cur.execute(
                """
                SELECT id, patient_name, ticket_no
                FROM patients
                WHERE ticket_no = %s
                """,
                (ticket,),
            )

            existing = cur.fetchall()

            if existing:
                conflicts.append(
                    (
                        patient["id"],
                        patient["patient_name"],
                        ticket,
                        existing,
                    )
                )

        if conflicts:
            print(
                f"\nWARNING: {len(conflicts)} "
                "ticket conflict(s) found:"
            )

            for sqlite_id, name, ticket, existing in conflicts:
                print(
                    f"  SQLite ID {sqlite_id} | "
                    f"{name} | Ticket {ticket}"
                )

                for row in existing:
                    print(
                        f"      PostgreSQL ID {row[0]} | "
                        f"{row[1]} | Ticket {row[2]}"
                    )
        else:
            print("  No ticket conflicts found.")

        # ----------------------------------------------------
        # Display exactly what WOULD be imported
        # ----------------------------------------------------

        print("\n" + "=" * 70)
        print("PATIENTS THAT WOULD BE IMPORTED")
        print("=" * 70)

        for patient in patients:
            print(
                f"\nSQLite ID: {patient['id']}"
            )
            print(
                f"  Date:       {patient['greg_date']}"
            )
            print(
                f"  Ethiopian:  {patient['eth_date']}"
            )
            print(
                f"  Patient:    {patient['patient_name']}"
            )
            print(
                f"  Ticket:     {patient['ticket_no']}"
            )
            print(
                f"  Procedure:  {patient['procedure']}"
            )
            print(
                f"  Fee:        {patient['total_fee']}"
            )
            print(
                f"  Doctor %:   {patient['doctor_pct']}"
            )
            print(
                f"  Earnings:   {patient['my_earning']}"
            )
            print(
                f"  Created:    {patient['created_at']}"
            )

        # ----------------------------------------------------
        # IMPORTANT: ROLLBACK
        # ----------------------------------------------------

        print("\n" + "=" * 70)
        print("DRY RUN COMPLETE")
        print("=" * 70)
        print("\nNO DATABASE CHANGES WERE MADE.")
        print(
            f"Patients examined: {len(patients)}"
        )
        print(
            f"PostgreSQL patients currently present: "
            f"{current_patient_count}"
        )
        print(
            f"Matching PostgreSQL doctor ID: "
            f"{pg_doctor_id}"
        )
        print(
            f"Ticket conflicts: {len(conflicts)}"
        )

        pg.rollback()

finally:
    pg.close()
    sqlite_conn.close()

print("\nPostgreSQL connection closed.")
print("SQLite backup closed.")