import sqlite3
from pathlib import Path
import crypto   # 👈 importer vårt nye crypto-modul

DB_FILE = Path("password_bank.db")


def init_db(db_file):
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service TEXT NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def add_account(db_file, key_file, service: str, username: str, password: str):
    enc_pass = crypto.encrypt_password(password, key_file)   # 👈 krypter passordet
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO accounts (service, username, password) VALUES (?, ?, ?)",
        (service, username, enc_pass),
    )
    conn.commit()
    conn.close()


def list_accounts(db_file):
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("SELECT id, service, username FROM accounts")
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_account_by_id(db_file, key_file, acc_id: int):
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("SELECT id, service, username, password FROM accounts WHERE id = ?", (acc_id,))
    account = cursor.fetchone()
    conn.close()

    if account:
        try:
            # Dekrypter passordet før retur
            dec_pass = crypto.decrypt_password(account[3], key_file)
        except Exception:
            # Returner None hvis dekryptering feiler
            return None
        return (account[0], account[1], account[2], dec_pass)
    return None


def get_account_meta_by_id(db_file, acc_id: int):
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("SELECT id, service, username FROM accounts WHERE id = ?", (acc_id,))
    account = cursor.fetchone()
    conn.close()
    return account  # (id, service, username) or None


def delete_account_by_id(db_file, acc_id: int):
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM accounts WHERE id = ?", (acc_id,))
    conn.commit()
    deleted = cursor.rowcount
    conn.close()
    return deleted > 0
