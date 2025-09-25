import sqlite3
from pathlib import Path
import crypto   # Import our crypto module

DB_FILE = Path("password_bank.db")


def _column_exists(cursor, table: str, column: str) -> bool:
    cursor.execute(f"PRAGMA table_info({table})")
    cols = [row[1] for row in cursor.fetchall()]
    return column in cols


def init_db(db_file):
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service TEXT NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            encryption_method TEXT NOT NULL
        )
    """)
    # Lightweight migration: add missing column if table pre-existed without it
    if not _column_exists(cursor, 'accounts', 'encryption_method'):
        cursor.execute("ALTER TABLE accounts ADD COLUMN encryption_method TEXT NOT NULL DEFAULT 'rsa'")
        cursor.execute("UPDATE accounts SET encryption_method = 'rsa' WHERE encryption_method IS NULL")
    conn.commit()
    conn.close()


def add_account(db_file, encryption_method, service: str, username: str, password: str, rsa_keys=None):
    enc_service = crypto.encrypt_password(service, encryption_method, rsa_keys=rsa_keys)
    enc_username = crypto.encrypt_password(username, encryption_method, rsa_keys=rsa_keys)
    enc_pass = crypto.encrypt_password(password, encryption_method, rsa_keys=rsa_keys)
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO accounts (service, username, password, encryption_method) VALUES (?, ?, ?, ?)",
        (enc_service, enc_username, enc_pass, encryption_method),
    )
    conn.commit()
    conn.close()


def list_accounts(db_file):
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("SELECT id, service, username, encryption_method FROM accounts")
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_account_by_id(db_file, acc_id: int):
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("SELECT id, service, username, password, encryption_method FROM accounts WHERE id = ?", (acc_id,))
    account = cursor.fetchone()
    conn.close()
    return account  # Return encrypted fields + method; decrypt in caller


def get_account_meta_by_id(db_file, acc_id: int):
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("SELECT id, service, username, encryption_method FROM accounts WHERE id = ?", (acc_id,))
    account = cursor.fetchone()
    conn.close()
    return account  # Return encrypted fields + method; decrypt in caller


def delete_account_by_id(db_file, acc_id: int):
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM accounts WHERE id = ?", (acc_id,))
    conn.commit()
    deleted = cursor.rowcount
    conn.close()
    return deleted > 0
