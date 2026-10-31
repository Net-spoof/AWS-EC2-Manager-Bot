"""Encrypted account vault and compact audit history. No plaintext credentials on disk."""
import os
import sqlite3
from pathlib import Path
from cryptography.fernet import Fernet


class Store:
    def __init__(self, db_path: str, fernet_key: str):
        if not fernet_key:
            raise ValueError('FERNET_KEY must be set and backed up securely')
        self.cipher = Fernet(fernet_key.encode())
        self.path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript('''
                CREATE TABLE IF NOT EXISTS accounts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alias TEXT NOT NULL UNIQUE,
                    kind TEXT NOT NULL CHECK(kind IN ('keys','role')),
                    payload BLOB NOT NULL,
                    aws_account_id TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS activity (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    account_id INTEGER,
                    operation TEXT NOT NULL,
                    region TEXT,
                    resource TEXT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
            ''')

    def _connect(self):
        conn = sqlite3.connect(self.path, timeout=15)
        conn.row_factory = sqlite3.Row
        return conn

    def add_account(self, alias: str, kind: str, payload: str, aws_account_id: str):
        if kind not in ('keys','role'):
            raise ValueError('Invalid account type')
        encrypted = self.cipher.encrypt(payload.encode())
        with self._connect() as conn:
            cur = conn.execute('INSERT INTO accounts (alias,kind,payload,aws_account_id) VALUES (?,?,?,?)',
                               (alias,kind,encrypted,aws_account_id))
            return cur.lastrowid

    def accounts(self):
        with self._connect() as conn:
            return [dict(row) for row in conn.execute('SELECT id,alias,kind,aws_account_id FROM accounts ORDER BY id')]

    def account(self, account_id: int):
        with self._connect() as conn:
            row = conn.execute('SELECT * FROM accounts WHERE id=?',(account_id,)).fetchone()
        if not row:
            raise ValueError('Account not found')
        acc = dict(row)
        acc['payload'] = self.cipher.decrypt(acc['payload']).decode()
        return acc

    def remove_account(self, account_id: int):
        with self._connect() as conn:
            conn.execute('DELETE FROM accounts WHERE id=?',(account_id,))

    def log(self, account_id, operation, region='', resource=''):
        with self._connect() as conn:
            conn.execute('INSERT INTO activity (account_id,operation,region,resource) VALUES (?,?,?,?)',
                         (account_id,operation,region,resource))

    def recent(self, limit=15):
        with self._connect() as conn:
            return [dict(r) for r in conn.execute('SELECT * FROM activity ORDER BY id DESC LIMIT ?', (limit,))]
