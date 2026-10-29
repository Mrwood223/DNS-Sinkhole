#!/usr/bin/env python3
"""Simple DNS sinkhole: blocks domains on a blocklist, forwards the rest upstream."""

import argparse
import asyncio
import logging
import socket

from dnslib import AAAA, A, DNSRecord, QTYPE, RCODE, RR

log = logging.getLogger("sinkhole")


def load_blocklist(path):
    """Load domains from a file. Supports one-domain-per-line and hosts-file format."""
    domains = set()
    with open(path) as f:
        for line in f:
            line = line.split("#")[0].strip().lower()
            if not line:
                continue
            domain = line.split()[-1].rstrip(".")  # last token works for both formats
            domains.add(domain)
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


class SinkholeProtocol(asyncio.DatagramProtocol):
    def __init__(self, blocklist, upstream):
        self.blocklist = blocklist
        self.upstream = upstream
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        asyncio.create_task(self.handle(data, addr))

    async def handle(self, data, addr):
        try:
            request = DNSRecord.parse(data)
            if not request.questions:
                return
            qname = str(request.q.qname).rstrip(".")
            qtype = QTYPE[request.q.qtype]
        except Exception:
            log.debug("Dropping malformed packet from %s", addr[0])
            return

        if is_blocked(qname, self.blocklist):
            reply = request.reply()
            if qtype == "A":
                reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A("0.0.0.0"), ttl=60))
            elif qtype == "AAAA":
                reply.add_answer(RR(request.q.qname, QTYPE.AAAA, rdata=AAAA("::"), ttl=60))
            self.transport.sendto(reply.pack(), addr)
            log.info("BLOCKED  %s  %s  from %s", qtype, qname, addr[0])
            return

        loop = asyncio.get_running_loop()
        try:
            response = await loop.run_in_executor(None, forward, data, self.upstream)
        except (socket.timeout, OSError):
            reply = request.reply()
            reply.header.rcode = RCODE.SERVFAIL
            response = reply.pack()
            log.warning("Upstream failure for %s", qname)
        self.transport.sendto(response, addr)
        log.info("ALLOWED  %s  %s  from %s", qtype, qname, addr[0])


async def main():
    parser = argparse.ArgumentParser(description="DNS sinkhole")
    parser.add_argument("--listen", default="0.0.0.0", help="address to bind")
    parser.add_argument("--port", type=int, default=5353, help="UDP port (use 53 as root)")
    parser.add_argument("--upstream", default="1.1.1.1", help="upstream DNS server")
    parser.add_argument("--blocklist", default="blocklist.txt", help="path to blocklist")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    blocklist = load_blocklist(args.blocklist)
    log.info("Loaded %d blocked domains", len(blocklist))

    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: SinkholeProtocol(blocklist, args.upstream),
        local_addr=(args.listen, args.port),
    )
    log.info("Listening on %s:%d, forwarding to %s", args.listen, args.port, args.upstream)
    try:
        await asyncio.Event().wait()
    finally:
        transport.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass