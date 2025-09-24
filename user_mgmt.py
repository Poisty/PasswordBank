import sqlite3
import os
import hashlib
import binascii

USERS_DB = 'users.db'
ITERATIONS = 100_000

# Ensure users.db exists
conn = sqlite3.connect(USERS_DB)
cursor = conn.cursor()
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL
    )
''')
conn.commit()
conn.close()

def hash_password(password: str, salt: bytes) -> str:
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, ITERATIONS)
    return binascii.hexlify(dk).decode()

def register_user(username: str, password: str) -> bool:
    if get_user(username):
        return False  # User exists
    salt = os.urandom(16)
    password_hash = hash_password(password, salt)
    conn = sqlite3.connect(USERS_DB)
    cursor = conn.cursor()
    cursor.execute('INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)',
                   (username, password_hash, binascii.hexlify(salt).decode()))
    conn.commit()
    conn.close()
    return True

def authenticate_user(username: str, password: str) -> bool:
    user = get_user(username)
    if not user:
        return False
    salt = binascii.unhexlify(user[2])
    password_hash = hash_password(password, salt)
    return password_hash == user[1]

def get_user(username: str):
    conn = sqlite3.connect(USERS_DB)
    cursor = conn.cursor()
    cursor.execute('SELECT username, password_hash, salt FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()
    return user

def get_user_db_file(username: str) -> str:
    return f'passwords_{username}.db'

def get_user_key_file(username: str) -> str:
    return f'secret_{username}.key'

