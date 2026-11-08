#!/usr/bin/env python3
"""Print a quick summary of the query log. A preview of what the dashboard will show."""

import argparse
import sqlite3


def main():
    parser = argparse.ArgumentParser(description="Summarize sinkhole query log")
    parser.add_argument("--db", default="queries.db")
    parser.add_argument("--limit", type=int, default=10)
    args = parser.parse_args()

    conn = sqlite3.connect(args.db)

    total = conn.execute("SELECT COUNT(*) FROM queries").fetchone()[0]
    if total == 0:
        print("No queries logged yet.")
        return

    print(f"Total queries: {total}\n")

    print("By action:")
    for action, count in conn.execute(
        "SELECT action, COUNT(*) FROM queries GROUP BY action ORDER BY 2 DESC"
    ):
        print(f"  {action:<8} {count:>7}  ({count / total:.1%})")

    print(f"\nTop {args.limit} blocked domains:")
    for domain, count in conn.execute(
        "SELECT domain, COUNT(*) FROM queries WHERE action='BLOCKED' "
        "GROUP BY domain ORDER BY 2 DESC LIMIT ?", (args.limit,)
    ):
        print(f"  {count:>7}  {domain}")

    print(f"\nTop {args.limit} clients:")
    for client, count in conn.execute(
        "SELECT client_ip, COUNT(*) FROM queries GROUP BY client_ip ORDER BY 2 DESC LIMIT ?",
        (args.limit,),
    ):
        print(f"  {count:>7}  {client}")

    avg_allowed, avg_cached = (
        conn.execute(
            "SELECT AVG(latency_ms) FROM queries WHERE action=?", (a,)
        ).fetchone()[0]
        for a in ("ALLOWED", "CACHED")
    )
    if avg_allowed is not None:
        print(f"\nAvg latency, forwarded: {avg_allowed:.1f} ms")
    if avg_cached is not None:
        print(f"Avg latency, cached:    {avg_cached:.1f} ms")


if __name__ == "__main__":
    main()