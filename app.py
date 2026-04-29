from flask import Flask, render_template, request, redirect, session, send_file
import psycopg2
import psycopg2.extras
from werkzeug.security import check_password_hash
from dotenv import load_dotenv
import os
import csv
import io
import pytz

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")

DATABASE_URL = os.environ.get("DATABASE_URL")


def get_db():
    return psycopg2.connect(DATABASE_URL)


def init_db():
    conn = get_db()
    cur = conn.cursor()

    with open("schema.sql", "r", encoding="utf-8") as f:
        cur.execute(f.read())

    conn.commit()
    cur.close()
    conn.close()


# ===================== 🔥 FIX AUDIT LOG =====================
def write_audit_log(
    action,
    user_id=None,
    username=None,
    unit_id=None,
    cyber_system_id=None,
    old_value=None,
    new_value=None,
    evaluator_name=None,
    assessment_date=None
):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO audit_logs
        (
            user_id,
            username,
            action,
            unit_id,
            cyber_system_id,
            old_value,
            new_value,
            evaluator_name,
            assessment_date,
            ip_address,
            user_agent
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (
        user_id if user_id is not None else session.get("user_id"),
        username if username is not None else session.get("username"),
        action,
        unit_id,
        cyber_system_id,
        str(old_value) if old_value is not None else None,
        str(new_value) if new_value is not None else None,
        evaluator_name,
        assessment_date,
        request.headers.get("X-Forwarded-For", request.remote_addr),
        request.headers.get("User-Agent")
    ))

    conn.commit()
    cur.close()
    conn.close()


@app.route("/")
def index():
    if "user_id" not in session:
        return redirect("/login")
    return redirect("/form")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = get_db()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cur.fetchone()

        cur.close()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            session["unit_id"] = user["unit_id"]

            write_audit_log("LOGIN_SUCCESS", user["id"], user["username"])
            return redirect("/form")

        write_audit_log("LOGIN_FAILED", username=username)
        return "Username or password is incorrect."

    return render_template("login.html")


@app.route("/logout")
def logout():
    if "user_id" in session:
        write_audit_log("LOGOUT")

    session.clear()
    return redirect("/login")


# ===================== 🔥 FORM =====================
@app.route("/form", methods=["GET", "POST"])
def form():
    if "user_id" not in session:
        return redirect("/login")

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    # ================= POST =================
    if request.method == "POST":
        unit_id = request.form["unit_id"]

        evaluator_name = request.form.get("evaluator_name", "").strip()
        assessment_date = request.form.get("assessment_date", "").strip()

        if not evaluator_name or not assessment_date:
            return "Evaluator name and assessment date are required."

        cur.execute("SELECT id FROM cyber_systems")
        systems = cur.fetchall()

        for system in systems:
            cyber_system_id = system["id"]
            checkbox_name = f"bes_{cyber_system_id}"
            new_is_bes = checkbox_name in request.form

            cur.execute("""
                SELECT is_bes
                FROM bes_records
                WHERE unit_id = %s AND cyber_system_id = %s
            """, (unit_id, cyber_system_id))

            old_record = cur.fetchone()
            old_is_bes = old_record["is_bes"] if old_record else None

            cur.execute("""
                INSERT INTO bes_records
                (
                    unit_id,
                    cyber_system_id,
                    is_bes,
                    evaluator_name,
                    assessment_date,
                    updated_by,
                    updated_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                ON CONFLICT (unit_id, cyber_system_id)
                DO UPDATE SET
                    is_bes = EXCLUDED.is_bes,
                    evaluator_name = EXCLUDED.evaluator_name,
                    assessment_date = EXCLUDED.assessment_date,
                    updated_by = EXCLUDED.updated_by,
                    updated_at = CURRENT_TIMESTAMP
            """, (
                unit_id,
                cyber_system_id,
                new_is_bes,
                evaluator_name,
                assessment_date,
                session["user_id"]
            ))

            if old_is_bes != new_is_bes:
                write_audit_log(
                    action="UPDATE_BES_RECORD",
                    unit_id=unit_id,
                    cyber_system_id=cyber_system_id,
                    old_value=old_is_bes,
                    new_value=new_is_bes,
                    evaluator_name=evaluator_name,
                    assessment_date=assessment_date
                )

        conn.commit()
        cur.close()
        conn.close()

        return redirect(f"/form?unit_id={unit_id}")

    # ================= GET =================
    cur.execute("SELECT * FROM units ORDER BY id")
    units = cur.fetchall()

    cur.execute("SELECT * FROM cyber_systems ORDER BY system_no")
    systems = cur.fetchall()

    selected_unit_id = request.args.get("unit_id")

    records = {}
    evaluator_name = ""
    assessment_date = ""

    if selected_unit_id:
        cur.execute("""
            SELECT cyber_system_id, is_bes
            FROM bes_records
            WHERE unit_id = %s
        """, (selected_unit_id,))
        rows = cur.fetchall()
        records = {row["cyber_system_id"]: row["is_bes"] for row in rows}

        # 🔥 ดึง evaluator ล่าสุด
        cur.execute("""
            SELECT evaluator_name, assessment_date
            FROM bes_records
            WHERE unit_id = %s
            AND evaluator_name IS NOT NULL
            ORDER BY updated_at DESC
            LIMIT 1
        """, (selected_unit_id,))
        meta = cur.fetchone()

        if meta:
            evaluator_name = meta["evaluator_name"] or ""
            assessment_date = meta["assessment_date"] or ""

    cur.close()
    conn.close()

    return render_template(
        "form.html",
        units=units,
        systems=systems,
        records=records,
        selected_unit_id=selected_unit_id,
        role=session["role"],
        user_unit_id=session["unit_id"],
        session=session,
        evaluator_name=evaluator_name,
        assessment_date=assessment_date
    )


# ===================== 🔥 EXPORT =====================
@app.route("/export")
def export_csv():
    if "user_id" not in session:
        return redirect("/login")

    write_audit_log("EXPORT_CSV")

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    cur.execute("""
        SELECT 
            u.unit_name,
            c.system_no,
            c.cyber_system_name,
            c.room_no,
            COALESCE(b.is_bes, false) AS is_bes,
            b.evaluator_name,
            b.assessment_date,
            b.updated_at
        FROM cyber_systems c
        CROSS JOIN units u
        LEFT JOIN bes_records b
            ON b.cyber_system_id = c.id
            AND b.unit_id = u.id
        ORDER BY u.id, c.system_no
    """)

    rows = cur.fetchall()
    cur.close()
    conn.close()

    thai_tz = pytz.timezone("Asia/Bangkok")

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "Unit Name",
        "No",
        "Cyber System Name",
        "Room No",
        "BES",
        "Evaluator Name",
        "Assessment Date",
        "Updated At"
    ])

    for row in rows:
        updated_at = row["updated_at"]

        if updated_at:
            if updated_at.tzinfo is None:
                updated_at = pytz.utc.localize(updated_at)

            thai_time = updated_at.astimezone(thai_tz)
            thai_year = thai_time.year + 543
            formatted_time = thai_time.strftime(f"%d/%m/{thai_year} %H:%M:%S")
        else:
            formatted_time = ""

        writer.writerow([
            row["unit_name"],
            row["system_no"],
            row["cyber_system_name"],
            row["room_no"],
            "Yes" if row["is_bes"] else "No",
            row["evaluator_name"] or "",
            row["assessment_date"] or "",
            formatted_time
        ])

    output.seek(0)

    return send_file(
        io.BytesIO(output.getvalue().encode("utf-8-sig")),
        mimetype="text/csv",
        as_attachment=True,
        download_name="bes_cyber_system_export.csv"
    )


if __name__ == "__main__":
    app.run(debug=True)

    