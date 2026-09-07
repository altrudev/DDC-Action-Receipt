"""Atomic replay reservation. Store is not an execution transaction coordinator."""
import sqlite3
from .crypto import sha256_digest

class ReplayStore:
    def __init__(self,path):
        self.db=sqlite3.connect(path, timeout=30, isolation_level=None)
        self.db.execute('PRAGMA busy_timeout=30000')
        self.db.execute('CREATE TABLE IF NOT EXISTS nonces (domain TEXT NOT NULL, nonce TEXT NOT NULL, digest TEXT NOT NULL, PRIMARY KEY(domain,nonce))')
    def reserve(self,domain,nonce,digest):
        try:
            self.db.execute('BEGIN IMMEDIATE')
            self.db.execute('INSERT INTO nonces VALUES (?,?,?)',(domain,nonce,digest))
            self.db.execute('COMMIT')
            return True
        except sqlite3.IntegrityError:
            self.db.execute('ROLLBACK'); return False
        except Exception:
            self.db.execute('ROLLBACK'); raise
    def close(self): self.db.close()
