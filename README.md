# DNS Sinkhole

A DNS server in Python that blocks ads, trackers, and malicious domains for every device on a network. Built to run on an Orange Pi.

## How it works

1. Receives DNS queries over UDP
2. Checks the domain (and its parent domains) against a blocklist
3. Blocked: returns `0.0.0.0` / `::`
4. Allowed: forwards to an upstream resolver and relays the answer

## Run it

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python sinkhole.py --port 5353
```

Test it:

```bash
dig @127.0.0.1 -p 5353 doubleclick.net   # should return 0.0.0.0
dig @127.0.0.1 -p 5353 example.com       # should resolve normally
```

To serve on the standard port 53, run as root or grant the capability:
`sudo setcap 'cap_net_bind_service=+ep' $(readlink -f $(which python3))`

## Roadmap

- [x] Forwarding resolver
- [x] Blocklist and sinkhole responses
- [ ] SQLite query logging
- [ ] Response caching (TTL-aware)
- [ ] Web dashboard (top blocked domains, per-device stats)
- [ ] DNS-over-TLS upstream
- [ ] Anomaly detection (DNS tunneling, query spikes)
- [ ] Docker packaging and systemd service