#!/usr/bin/env python3
"""Web dashboard for the DNS sinkhole. Reads the SQLite query log; never writes to it."""

import argparse
import sqlite3
import time

from flask import Flask, jsonify, render_template, request

app = Flask(__name__)
app.config["DB_PATH"] = "queries.db"


def get_db():
    conn = sqlite3.connect(app.config["DB_PATH"], timeout=5)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only=ON")  # the dashboard is strictly read-only
    return conn


def since_ts():
    """Start of the time window from ?hours=, clamped to 15 minutes .. 30 days."""
    hours = min(max(request.args.get("hours", 24, type=float), 0.25), 24 * 30)
    return time.time() - hours * 3600, hours


def limit_arg(default, maximum=100):
    return min(max(request.args.get("limit", default, type=int), 1), maximum)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/summary")
def summary():
    start, _ = since_ts()
    with get_db() as conn:
        row = conn.execute(
            """
            SELECT COUNT(*)                                          AS total,
                   SUM(action = 'BLOCKED')                           AS blocked,
                   SUM(action = 'CACHED')                            AS cached,
                   SUM(action = 'ALLOWED')                           AS allowed,
                   SUM(action = 'ERROR')                             AS errors,
                   COUNT(DISTINCT client_ip)                         AS clients,
                   AVG(CASE WHEN action = 'ALLOWED' THEN latency_ms END) AS avg_forward_ms,
                   AVG(CASE WHEN action = 'CACHED'  THEN latency_ms END) AS avg_cached_ms
            FROM queries WHERE ts >= ?
            """,
            (start,),
        ).fetchone()
    total = row["total"] or 0
    blocked = row["blocked"] or 0
    return jsonify(
        total=total,
        blocked=blocked,
        cached=row["cached"] or 0,
        allowed=row["allowed"] or 0,
        errors=row["errors"] or 0,
        clients=row["clients"] or 0,
        block_pct=round(100 * blocked / total, 1) if total else 0,
        avg_forward_ms=row["avg_forward_ms"],
        avg_cached_ms=row["avg_cached_ms"],
    )


@app.route("/api/timeline")
def timeline():
    start, hours = since_ts()
    bucket = 300 if hours <= 6 else 3600  # 5-minute or 1-hour buckets
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT CAST(ts / ? AS INTEGER) * ? AS bucket,
                   COUNT(*)                    AS total,
                   SUM(action = 'BLOCKED')     AS blocked
            FROM queries WHERE ts >= ?
            GROUP BY bucket ORDER BY bucket
            """,
            (bucket, bucket, start),
        ).fetchall()
    return jsonify(
        [{"t": r["bucket"] * 1000, "total": r["total"], "blocked": r["blocked"] or 0} for r in rows]
    )


@app.route("/api/top-blocked")
def top_blocked():
    start, _ = since_ts()
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT domain, COUNT(*) AS count FROM queries
            WHERE ts >= ? AND action = 'BLOCKED'
            GROUP BY domain ORDER BY count DESC LIMIT ?
            """,
            (start, limit_arg(10)),
        ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/clients")
def clients():
    start, _ = since_ts()
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT client_ip,
                   COUNT(*)                AS total,
                   SUM(action = 'BLOCKED') AS blocked
            FROM queries WHERE ts >= ?
            GROUP BY client_ip ORDER BY total DESC LIMIT ?
            """,
            (start, limit_arg(10)),
        ).fetchall()
    return jsonify(
        [{"client_ip": r["client_ip"], "total": r["total"], "blocked": r["blocked"] or 0} for r in rows]
    )


@app.route("/api/recent")
def recent():
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT ts, client_ip, domain, qtype, action, latency_ms
            FROM queries ORDER BY id DESC LIMIT ?
            """,
            (limit_arg(25, 200),),
        ).fetchall()
    return jsonify([dict(r) for r in rows])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DNS sinkhole dashboard")
    parser.add_argument("--db", default="queries.db", help="path to the SQLite query log")
    parser.add_argument("--host", default="127.0.0.1", help="use 0.0.0.0 to reach it from your LAN")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()

    app.config["DB_PATH"] = args.db
    app.run(host=args.host, port=args.port)