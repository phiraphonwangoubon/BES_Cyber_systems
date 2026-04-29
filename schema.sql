CREATE TABLE IF NOT EXISTS units (
    id SERIAL PRIMARY KEY,
    unit_name TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'unit_user',
    unit_id INTEGER REFERENCES units(id)
);

CREATE TABLE IF NOT EXISTS cyber_systems (
    id SERIAL PRIMARY KEY,
    system_no INTEGER NOT NULL,
    cyber_system_name TEXT NOT NULL,
    room_no TEXT
);

CREATE TABLE IF NOT EXISTS bes_records (
    id SERIAL PRIMARY KEY,
    unit_id INTEGER NOT NULL REFERENCES units(id),
    cyber_system_id INTEGER NOT NULL REFERENCES cyber_systems(id),
    is_bes BOOLEAN NOT NULL DEFAULT FALSE,
    evaluator_name TEXT,
    assessment_date DATE,
    updated_by INTEGER REFERENCES users(id),
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(unit_id, cyber_system_id)
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER,
    username TEXT,
    action TEXT NOT NULL,
    unit_id INTEGER,
    cyber_system_id INTEGER,
    old_value TEXT,
    new_value TEXT,
    evaluator_name TEXT,
    assessment_date DATE,
    ip_address TEXT,
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);