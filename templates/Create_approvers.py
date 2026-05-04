import os
import psycopg2
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash

load_dotenv()

DATABASE_URL = os.environ.get("DATABASE_URL")

conn = psycopg2.connect(DATABASE_URL)
cur = conn.cursor()

# ดึง unit ทั้งหมด
cur.execute("SELECT id, unit_name FROM units ORDER BY id")
units = cur.fetchall()

for unit_id, unit_name in units:
    username = f"approver_{unit_id}"
    password = "123456"  # เปลี่ยนทีหลังได้
    password_hash = generate_password_hash(password)

    cur.execute("""
        INSERT INTO users (username, password_hash, role, unit_id)
        VALUES (%s, %s, %s, %s)
        ON CONFLICT (username) DO NOTHING;
    """, (username, password_hash, "approver", unit_id))

    print(f"Created: {username} (unit {unit_name})")

conn.commit()
cur.close()
conn.close()

print("✅ Done creating approvers")