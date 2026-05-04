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


def can_access_unit(unit_id):
    if "user_id" not in session:
        return False

    if session.get("role") == "admin":
        return True

    user_unit_id = session.get("unit_id")

    if user_unit_id is None:
        return False

    return int(user_unit_id) == int(unit_id)


def can_approve_unit(unit_id):
    if session.get("role") == "admin":
        return True

    if session.get("role") == "approver":
        return can_access_unit(unit_id)

    return False


def get_units_for_current_user(cur):
    if session.get("role") == "admin":
        cur.execute("SELECT * FROM units ORDER BY id")
        return cur.fetchall()

    cur.execute("""
        SELECT *
        FROM units
        WHERE id = %s
        ORDER BY id
    """, (session.get("unit_id"),))
    return cur.fetchall()


def get_client_ip():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if ip:
        ip = ip.split(",")[0].strip()
    return ip


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
        get_client_ip(),
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

            write_audit_log(
                action="LOGIN_SUCCESS",
                user_id=user["id"],
                username=user["username"]
            )

            if user["role"] == "approver":
                return redirect("/approver")
            else:
                return redirect("/form")

        write_audit_log(
            action="LOGIN_FAILED",
            username=username
        )

        return "Username or password is incorrect."

    return render_template("login.html")


@app.route("/logout")
def logout():
    if "user_id" in session:
        write_audit_log("LOGOUT")

    session.clear()
    return redirect("/login")


@app.route("/form", methods=["GET", "POST"])
def form():

    if session.get("role") == "approver":
        return redirect("/approver")


    if "user_id" not in session:
        return redirect("/login")

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    if request.method == "POST":
        unit_id = request.form["unit_id"]

        if not can_access_unit(unit_id):
            cur.close()
            conn.close()
            write_audit_log(
                action="ACCESS_DENIED_FORM_POST",
                unit_id=unit_id,
                new_value="User attempted to submit BES record for unauthorized unit"
            )
            return "Access denied: You cannot edit this unit."

        evaluator_name = request.form.get("evaluator_name", "").strip()
        assessment_date = request.form.get("assessment_date", "").strip()

        if not evaluator_name or not assessment_date:
            cur.close()
            conn.close()
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

    units = get_units_for_current_user(cur)

    cur.execute("SELECT * FROM cyber_systems ORDER BY system_no")
    systems = cur.fetchall()

    selected_unit_id = request.args.get("unit_id")

    if selected_unit_id and not can_access_unit(selected_unit_id):
        cur.close()
        conn.close()
        write_audit_log(
            action="ACCESS_DENIED_FORM_VIEW",
            unit_id=selected_unit_id,
            new_value="User attempted to view BES form for unauthorized unit"
        )
        return "Access denied: You cannot view this unit."

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


@app.route("/f05", methods=["GET", "POST"])
def f05():

    if session.get("role") == "approver":
        return redirect("/approver")


    if "user_id" not in session:
        return redirect("/login")

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    if request.method == "POST":
        unit_id = request.form["unit_id"]

        if not can_access_unit(unit_id):
            cur.close()
            conn.close()
            write_audit_log(
                action="ACCESS_DENIED_F05_POST",
                unit_id=unit_id,
                new_value="User attempted to submit F05 for unauthorized unit"
            )
            return "Access denied: You cannot edit this unit."

        applicability = "applicability" in request.form
        asset_consideration = "asset_consideration" in request.form
        bes_identification = "bes_identification" in request.form
        asset_identification = "asset_identification" in request.form

        form_old_1 = request.form.get("form_old_1", "").strip()
        form_new_1 = request.form.get("form_new_1", "").strip()
        form_old_2 = request.form.get("form_old_2", "").strip()
        form_new_2 = request.form.get("form_new_2", "").strip()
        form_old_3 = request.form.get("form_old_3", "").strip()
        form_new_3 = request.form.get("form_new_3", "").strip()
        form_old_4 = request.form.get("form_old_4", "").strip()
        form_new_4 = request.form.get("form_new_4", "").strip()

        improvement_detail = request.form.get("improvement_detail", "").strip()
        operator_name = request.form.get("operator_name", "").strip()
        assessment_date = request.form.get("assessment_date", "").strip()

        if not operator_name or not assessment_date:
            cur.close()
            conn.close()
            return "Operator name and assessment date are required."

        cur.execute("""
            INSERT INTO f05_records
            (
                unit_id,
                applicability,
                asset_consideration,
                bes_identification,
                asset_identification,
                form_old_1,
                form_new_1,
                form_old_2,
                form_new_2,
                form_old_3,
                form_new_3,
                form_old_4,
                form_new_4,
                improvement_detail,
                operator_name,
                assessment_date,
                approval_status,
                approved_by,
                approved_at,
                approval_comment,
                approval_evaluator_name,
                updated_by,
                updated_at
            )
            VALUES (
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s,
                'pending',
                NULL,
                NULL,
                NULL,
                NULL,
                %s,
                CURRENT_TIMESTAMP
            )
            ON CONFLICT (unit_id)
            DO UPDATE SET
                applicability = EXCLUDED.applicability,
                asset_consideration = EXCLUDED.asset_consideration,
                bes_identification = EXCLUDED.bes_identification,
                asset_identification = EXCLUDED.asset_identification,
                form_old_1 = EXCLUDED.form_old_1,
                form_new_1 = EXCLUDED.form_new_1,
                form_old_2 = EXCLUDED.form_old_2,
                form_new_2 = EXCLUDED.form_new_2,
                form_old_3 = EXCLUDED.form_old_3,
                form_new_3 = EXCLUDED.form_new_3,
                form_old_4 = EXCLUDED.form_old_4,
                form_new_4 = EXCLUDED.form_new_4,
                improvement_detail = EXCLUDED.improvement_detail,
                operator_name = EXCLUDED.operator_name,
                assessment_date = EXCLUDED.assessment_date,
                approval_status = 'pending',
                approved_by = NULL,
                approved_at = NULL,
                approval_comment = NULL,
                approval_evaluator_name = NULL,
                updated_by = EXCLUDED.updated_by,
                updated_at = CURRENT_TIMESTAMP
        """, (
            unit_id,
            applicability,
            asset_consideration,
            bes_identification,
            asset_identification,
            form_old_1,
            form_new_1,
            form_old_2,
            form_new_2,
            form_old_3,
            form_new_3,
            form_old_4,
            form_new_4,
            improvement_detail,
            operator_name,
            assessment_date if assessment_date else None,
            session["user_id"]
        ))

        cur.execute("""
            INSERT INTO f05_history
            (
                f05_id,
                action,
                status,
                user_id,
                username,
                comment
            )
            VALUES (
                (SELECT id FROM f05_records WHERE unit_id = %s),
                'submit',
                'pending',
                %s,
                %s,
                %s
            )
        """, (
            unit_id,
            session["user_id"],
            session["username"],
            "Submitted F05 document"
        ))

        write_audit_log(
            action="SUBMIT_F05_RECORD",
            unit_id=unit_id,
            old_value=None,
            new_value="F05 submitted and waiting for approval",
            evaluator_name=operator_name,
            assessment_date=assessment_date if assessment_date else None
        )

        conn.commit()
        cur.close()
        conn.close()

        return redirect(f"/f05?unit_id={unit_id}")

    units = get_units_for_current_user(cur)

    selected_unit_id = request.args.get("unit_id")

    if selected_unit_id and not can_access_unit(selected_unit_id):
        cur.close()
        conn.close()
        write_audit_log(
            action="ACCESS_DENIED_F05_VIEW",
            unit_id=selected_unit_id,
            new_value="User attempted to view F05 for unauthorized unit"
        )
        return "Access denied: You cannot view this unit."

    record = None

    if selected_unit_id:
        cur.execute("""
            SELECT *
            FROM f05_records
            WHERE unit_id = %s
        """, (selected_unit_id,))
        record = cur.fetchone()
        
        import pytz

        thai_tz = pytz.timezone("Asia/Bangkok")

        if record and record["approved_at"]:
                utc_time = record["approved_at"]

                if utc_time.tzinfo is None:
                    utc_time = pytz.utc.localize(utc_time)

                thai_time = utc_time.astimezone(thai_tz)

                thai_year = thai_time.year + 543

                record["approved_at_th"] = thai_time.strftime(
    f"%d/%m/{thai_year} %H:%M:%S"
)
        

    cur.close()
    conn.close()

    return render_template(
        "f05.html",
        units=units,
        selected_unit_id=selected_unit_id,
        record=record,
        session=session
    )


@app.route("/approver")
def approver():
    if "user_id" not in session:
        return redirect("/login")

    if session.get("role") not in ["approver", "admin"]:
        return "Access denied: approver only"

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    if session.get("role") == "admin":
        cur.execute("""
            SELECT
                f.id,
                f.unit_id,
                u.unit_name,
                f.operator_name,
                f.assessment_date,
                f.approval_status,
                f.approval_comment,
                f.approval_evaluator_name,
                f.approved_at,
                f.updated_at
            FROM f05_records f
            JOIN units u ON f.unit_id = u.id
            ORDER BY f.updated_at DESC
        """)
    else:
        cur.execute("""
            SELECT
                f.id,
                f.unit_id,
                u.unit_name,
                f.operator_name,
                f.assessment_date,
                f.approval_status,
                f.approval_comment,
                f.approval_evaluator_name,
                f.approved_at,
                f.updated_at
            FROM f05_records f
            JOIN units u ON f.unit_id = u.id
            WHERE f.unit_id = %s
            ORDER BY f.updated_at DESC
        """, (session.get("unit_id"),))

    records = cur.fetchall()

    import pytz

    thai_tz = pytz.timezone("Asia/Bangkok")

    for r in records:
        # approved_at
        if r["approved_at"]:
            utc_time = r["approved_at"]

            if utc_time.tzinfo is None:
                utc_time = pytz.utc.localize(utc_time)

            thai_time = utc_time.astimezone(thai_tz)
            thai_year = thai_time.year + 543

            r["approved_at_th"] = thai_time.strftime(
                f"%d/%m/{thai_year} %H:%M:%S"
            )

        # updated_at
        if r["updated_at"]:
            utc_time = r["updated_at"]

            if utc_time.tzinfo is None:
                utc_time = pytz.utc.localize(utc_time)

            thai_time = utc_time.astimezone(thai_tz)
            thai_year = thai_time.year + 543

            r["updated_at_th"] = thai_time.strftime(
                f"%d/%m/{thai_year} %H:%M:%S"
            )

    cur.close()
    conn.close()

    return render_template(
        "approver.html",
        records=records,
        session=session
    )


@app.route("/approver/f05/<int:unit_id>")
def approver_f05_detail(unit_id):
    if "user_id" not in session:
        return redirect("/login")

    if not can_approve_unit(unit_id):
        write_audit_log(
            action="ACCESS_DENIED_APPROVER_DETAIL",
            unit_id=unit_id,
            new_value="User attempted to view approver detail for unauthorized unit"
        )
        return "Access denied: You cannot approve this unit."

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    cur.execute("""
        SELECT
            f.*,
            u.unit_name,
            approver.username AS approved_by_username
        FROM f05_records f
        JOIN units u ON f.unit_id = u.id
        LEFT JOIN users approver ON f.approved_by = approver.id
        WHERE f.unit_id = %s
    """, (unit_id,))
    record = cur.fetchone()

    if not record:
        cur.close()
        conn.close()
        return "F05 document not found."

    cur.execute("""
        SELECT *
        FROM f05_history
        WHERE f05_id = %s
        ORDER BY created_at DESC
    """, (record["id"],))
    history = cur.fetchall()

    cur.close()
    conn.close()

    return render_template(
        "approver_f05_detail.html",
        record=record,
        history=history,
        session=session
    )


@app.route("/approver/f05/<int:unit_id>/decision", methods=["POST"])
def approve_f05_decision(unit_id):
    if "user_id" not in session:
        return redirect("/login")

    if not can_approve_unit(unit_id):
        write_audit_log(
            action="ACCESS_DENIED_APPROVER_DECISION",
            unit_id=unit_id,
            new_value="User attempted to approve/reject unauthorized unit"
        )
        return "Access denied: You cannot approve this unit."

    decision = request.form.get("decision")
    approval_comment = request.form.get("approval_comment", "").strip()
    approval_evaluator_name = request.form.get("approval_evaluator_name", "").strip()

    if decision not in ["approved", "rejected"]:
        return "Invalid approval decision."

    if not approval_evaluator_name:
        return "Please enter approval evaluator name."

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    cur.execute("""
        SELECT id
        FROM f05_records
        WHERE unit_id = %s
    """, (unit_id,))
    record = cur.fetchone()

    if not record:
        cur.close()
        conn.close()
        return "F05 document not found."

    cur.execute("""
        UPDATE f05_records
        SET
            approval_status = %s,
            approved_by = %s,
            approved_at = CURRENT_TIMESTAMP,
            approval_comment = %s,
            approval_evaluator_name = %s
        WHERE unit_id = %s
    """, (
        decision,
        session["user_id"],
        approval_comment,
        approval_evaluator_name,
        unit_id
    ))

    history_action = "approve" if decision == "approved" else "reject"

    cur.execute("""
        INSERT INTO f05_history
        (
            f05_id,
            action,
            status,
            user_id,
            username,
            comment
        )
        VALUES (%s, %s, %s, %s, %s, %s)
    """, (
        record["id"],
        history_action,
        decision,
        session["user_id"],
        session["username"],
        approval_comment
    ))

    conn.commit()
    cur.close()
    conn.close()

    write_audit_log(
        action="APPROVE_F05_RECORD" if decision == "approved" else "REJECT_F05_RECORD",
        unit_id=unit_id,
        old_value=None,
        new_value=decision,
        evaluator_name=approval_evaluator_name
    )

    return redirect("/approver")


@app.route("/export")
def export_csv():
    if "user_id" not in session:
        return redirect("/login")

    write_audit_log("EXPORT_CSV")

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    if session.get("role") == "admin":
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
    else:
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
            WHERE u.id = %s
            ORDER BY u.id, c.system_no
        """, (session.get("unit_id"),))

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
@app.route("/f05/report/<int:unit_id>")
def f05_report(unit_id):
    if "user_id" not in session:
        return redirect("/login")

    if not can_access_unit(unit_id):
        return "Access denied: You cannot view this report."

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    cur.execute("""
        SELECT
            f.*,
            u.unit_name,
            approver.username AS approved_by_username
        FROM f05_records f
        JOIN units u ON f.unit_id = u.id
        LEFT JOIN users approver ON f.approved_by = approver.id
        WHERE f.unit_id = %s
    """, (unit_id,))

    record = cur.fetchone()

    cur.close()
    conn.close()

    if not record:
        return "F05 report not found."

    thai_tz = pytz.timezone("Asia/Bangkok")

    if record["approved_at"]:
        utc_time = record["approved_at"]

        if utc_time.tzinfo is None:
            utc_time = pytz.utc.localize(utc_time)

        thai_time = utc_time.astimezone(thai_tz)
        thai_year = thai_time.year + 543

        record["approved_at_th"] = thai_time.strftime(
            f"%d/%m/{thai_year} %H:%M:%S"
        )

    return render_template(
        "f05_report.html",
        record=record,
        session=session
    )

@app.route("/f03/report/<int:unit_id>")
def f03_report(unit_id):
    if "user_id" not in session:
        return redirect("/login")

    if not can_access_unit(unit_id):
        return "Access denied: You cannot view this report."

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    cur.execute("""
        SELECT unit_name
        FROM units
        WHERE id = %s
    """, (unit_id,))
    unit = cur.fetchone()

    cur.execute("""
        SELECT
            c.system_no,
            c.cyber_system_name,
            c.room_no,
            COALESCE(b.is_bes, false) AS is_bes,
            b.evaluator_name,
            b.assessment_date,
            b.updated_at
        FROM cyber_systems c
        LEFT JOIN bes_records b
            ON b.cyber_system_id = c.id
            AND b.unit_id = %s
        ORDER BY c.system_no
    """, (unit_id,))
    records = cur.fetchall()

    evaluator_name = ""
    assessment_date = ""

    for r in records:
        if r["evaluator_name"]:
            evaluator_name = r["evaluator_name"]
            assessment_date = r["assessment_date"]
            break

    cur.close()
    conn.close()

    return render_template(
        "f03_report.html",
        unit=unit,
        records=records,
        evaluator_name=evaluator_name,
        assessment_date=assessment_date,
        session=session
    )

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)