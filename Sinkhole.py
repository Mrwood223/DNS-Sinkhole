#!/usr/bin/env python3
"""DNS sinkhole: blocks domains on a blocklist, caches and forwards the rest upstream."""

import argparse
import asyncio
import logging
import socket
import time

from dnslib import AAAA, A, DNSRecord, QTYPE, RCODE, RR

from querylog import QueryLogger

log = logging.getLogger("sinkhole")

MAX_CACHE_TTL = 3600  # never cache longer than an hour


def load_blocklist(path):
    """Load domains from a file. Supports one-domain-per-line and hosts-file format."""
    domains = set()
    with open(path) as f:
        for line in f:
            line = line.split("#")[0].strip().lower()
            if not line:
                continue
            domains.add(line.split()[-1].rstrip("."))
    return domains


def is_blocked(name, blocklist):
    """True if the name or any parent domain is on the blocklist."""
    labels = name.rstrip(".").lower().split(".")
    return any(".".join(labels[i:]) in blocklist for i in range(len(labels)))


def forward(data, upstream, timeout=3.0):
    """Send the raw query to the upstream resolver and return the raw response."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(data, (upstream, 53))
        response, _ = s.recvfrom(4096)
        return response


def cacheable_ttl(response):
    """Return how many seconds a response may be cached (0 = don't cache)."""
    try:
        record = DNSRecord.parse(response)
    except Exception:
        return 0
    if record.header.rcode != RCODE.NOERROR or record.header.tc or not record.rr:
        return 0
    return min(MAX_CACHE_TTL, min(rr.ttl for rr in record.rr))


class TTLCache:
    """Tiny in-memory cache keyed by (domain, qtype). Entries expire after their TTL."""

    def __init__(self, max_entries=5000):
        self.max_entries = max_entries
        self._data = {}

    def get(self, key):
        item = self._data.get(key)
        if item is None:
            return None
        expires, response = item
        if time.monotonic() >= expires:
            del self._data[key]
            return None
        return response

    def put(self, key, response, ttl):
        if ttl <= 0:
            return
        if len(self._data) >= self.max_entries:
            self._data.pop(next(iter(self._data)))  # evict oldest inserted entry
        self._data[key] = (time.monotonic() + ttl, response)


class SinkholeProtocol(asyncio.DatagramProtocol):
    def __init__(self, blocklist, upstream, cache, querylog):
        self.blocklist = blocklist
        self.upstream = upstream
        self.cache = cache
        self.querylog = querylog
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        asyncio.create_task(self.handle(data, addr))

    async def handle(self, data, addr):
        start = time.perf_counter()
        try:
            request = DNSRecord.parse(data)
            if not request.questions:
                return
            qname = str(request.q.qname).rstrip(".")
            qtype = QTYPE[request.q.qtype]
        except Exception:
            log.debug("Dropping malformed packet from %s", addr[0])
            return

        client = addr[0]

        def record(action):
            ms = (time.perf_counter() - start) * 1000
            log.info("%-8s %-5s %s  from %s  (%.1f ms)", action, qtype, qname, client, ms)
            if self.querylog:
                self.querylog.log(client, qname, qtype, action, ms)

        # 1. Blocked: answer with a null address
        if is_blocked(qname, self.blocklist):
            reply = request.reply()
            if qtype == "A":
                reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A("0.0.0.0"), ttl=60))
            elif qtype == "AAAA":
                reply.add_answer(RR(request.q.qname, QTYPE.AAAA, rdata=AAAA("::"), ttl=60))
            self.transport.sendto(reply.pack(), addr)
            record("BLOCKED")
            return

        # 2. Cached: reuse the stored answer, swapping in this query's transaction ID
        key = (qname.lower(), qtype)
        cached = self.cache.get(key)
        if cached is not None:
            self.transport.sendto(data[:2] + cached[2:], addr)
            record("CACHED")
            return

        # 3. Forward upstream (in a thread so we never block the event loop)
        loop = asyncio.get_running_loop()
        try:
            response = await loop.run_in_executor(None, forward, data, self.upstream)
        except (socket.timeout, OSError):
            reply = request.reply()
            reply.header.rcode = RCODE.SERVFAIL
            self.transport.sendto(reply.pack(), addr)
            record("ERROR")
            return

        self.cache.put(key, response, cacheable_ttl(response))
        self.transport.sendto(response, addr)
        record("ALLOWED")


async def main():
    parser = argparse.ArgumentParser(description="DNS sinkhole")
    parser.add_argument("--listen", default="0.0.0.0", help="address to bind")
    parser.add_argument("--port", type=int, default=5353, help="UDP port (use 53 as root)")
    parser.add_argument("--upstream", default="1.1.1.1", help="upstream DNS server")
    parser.add_argument("--blocklist", default="blocklist.txt", help="path to blocklist")
    parser.add_argument("--db", default="queries.db", help="SQLite log file ('' to disable)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    blocklist = load_blocklist(args.blocklist)
    log.info("Loaded %d blocked domains", len(blocklist))

    querylog = QueryLogger(args.db) if args.db else None
    flusher = asyncio.create_task(querylog.run_flusher()) if querylog else None

    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: SinkholeProtocol(blocklist, args.upstream, TTLCache(), querylog),
        local_addr=(args.listen, args.port),
    )
    log.info("Listening on %s:%d, forwarding to %s", args.listen, args.port, args.upstream)
    try:
        await asyncio.Event().wait()
    finally:
        transport.close()
        if flusher:
            flusher.cancel()
        if querylog:
            querylog.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass