"""SQLite query logging. Writes are batched to limit disk wear (good for SD cards)."""

import asyncio
import sqlite3
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS queries (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         REAL NOT NULL,
    client_ip  TEXT NOT NULL,
    domain     TEXT NOT NULL,
    qtype      TEXT NOT NULL,
    action     TEXT NOT NULL,   -- BLOCKED | ALLOWED | CACHED | ERROR
    latency_ms REAL
);
CREATE INDEX IF NOT EXISTS idx_queries_ts ON queries(ts);
CREATE INDEX IF NOT EXISTS idx_queries_domain ON queries(domain);
CREATE INDEX IF NOT EXISTS idx_queries_client ON queries(client_ip);
"""


class QueryLogger:
    def __init__(self, path, flush_interval=5.0):
        self.conn = sqlite3.connect(path)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(SCHEMA)
        self.flush_interval = flush_interval
        self._dirty = False

    def log(self, client_ip, domain, qtype, action, latency_ms=None):
        self.conn.execute(
            "INSERT INTO queries (ts, client_ip, domain, qtype, action, latency_ms) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (time.time(), client_ip, domain.lower(), qtype, action, latency_ms),
        )
        self._dirty = True

    def flush(self):
        if self._dirty:
            self.conn.commit()
            self._dirty = False

    async def run_flusher(self):
        """Background task: commit pending writes every few seconds."""
        while True:
            await asyncio.sleep(self.flush_interval)
            self.flush()

    def close(self):
        self.flush()
        self.conn.close()