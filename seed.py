import os
import psycopg2
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash

load_dotenv()

DATABASE_URL = os.environ.get("DATABASE_URL")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not set. Please check your .env file.")

conn = psycopg2.connect(DATABASE_URL)
cur = conn.cursor()

# ล้างข้อมูล checklist และรายการ cyber systems เดิม
# ไม่ล้าง users และ units เพื่อไม่ให้ user login หาย
cur.execute("""
    TRUNCATE TABLE bes_records, cyber_systems
    RESTART IDENTITY CASCADE;
""")

units = [
    "โรงไฟฟ้า A",
    "โรงไฟฟ้า B",
    "โรงไฟฟ้า C",
    "โรงไฟฟ้า D",
    "โรงไฟฟ้า E",
    "โรงไฟฟ้า F",
    "โรงไฟฟ้า G",
    "โรงไฟฟ้า H",
    "โรงไฟฟ้า I",
    "โรงไฟฟ้า J",
    "โรงไฟฟ้า K",
    "โรงไฟฟ้า L",
    "โรงไฟฟ้า M",
    "โรงไฟฟ้า N",
    "โรงไฟฟ้า O",
    "โรงไฟฟ้า P",
    "โรงไฟฟ้า Q",
    "โรงไฟฟ้า R",
    "โรงไฟฟ้า S",
]

for unit in units:
    cur.execute("""
        INSERT INTO units (unit_name)
        VALUES (%s)
        ON CONFLICT (unit_name) DO NOTHING;
    """, (unit,))

systems = [
    (1, "Automatic Generation Control (AGC)", "CCR"),
    (2, "Boiler Control and Protection (BCP)", "PCC41, PCC42, PCC40"),
    (3, "Machine Monitoring System (MMS)", "PCC41, PCC42, PCC40"),
    (4, "SCADA", "CCR"),
    (5, "Speed Frequency Control (SFC)", "PCC41, PCC42"),
    (6, "Automatic Voltage Control (AVR)", "PCC41, PCC42"),
    (7, "Startup Sequence Control (SSC)", "PCC41, PCC42"),
    (8, "Automatic Turbine Startup (ATS)", "PCC40"),
    (9, "Operator Station (OST)", "CCR"),
    (10, "Data Historical System", "CCR"),
    (11, "Alarm Sequence Display", "CCR"),
    (12, "Terminal Server", "CCR"),
    (13, "Engineering Station", "CCR"),
    (14, "Power Diagnostic System", "CCR"),
    (15, "Windows Transient Stability (WINTS)", "CCR"),
    (16, "Time Server (TiS)", "CCR"),
    (17, "Communication Station (CS3000)", "CCR"),
    (18, "Application Server", "CCR"),
    (19, "Security Server", "CCR"),
    (20, "Firewall", "CCR"),
    (21, "Router", "CCR"),
    (22, "Network Storage", "CCR"),
    (23, "OPC Server", "CCR"),
    (24, "Printer Station", "PCC41, PCC42, PCC40, CCR"),
    (25, "Sequence of Event (SOE)", "CCR"),
    (26, "Anti-Virus Server", "CCR"),
    (27, "UPS System", "CCR"),
]

for system_no, name, room in systems:
    cur.execute("""
        INSERT INTO cyber_systems (system_no, cyber_system_name, room_no)
        VALUES (%s, %s, %s);
    """, (system_no, name, room))

password_hash = generate_password_hash("admin123")

cur.execute("""
    INSERT INTO users (username, password_hash, role, unit_id)
    VALUES (%s, %s, %s, NULL)
    ON CONFLICT (username) DO NOTHING;
""", ("admin", password_hash, "admin"))

conn.commit()
cur.close()
conn.close()

print("Seed data completed successfully.")