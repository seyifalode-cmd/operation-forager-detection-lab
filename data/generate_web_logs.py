"""
OPERATION FORAGER — Web Log Generator
======================================
Generates synthetic web access logs simulating Stage 1 of the FORAGER intrusion:
credential stuffing at scale using a rotating proxy pool.

Design details:
  - 40,000 attack attempts spread across only 900 IP addresses
  - Mimics a rotating proxy pool — what makes credential stuffing hard to catch
    with simple per-IP rate rules
  - Attack events are buried in realistic background traffic at real-world ratios
  - Every event carries a hidden __label__ field for validation scoring
    (real logs never have this — it exists only for measurement)

Output: data/web_logs.jsonl
"""

import json
import random
import ipaddress
from datetime import datetime, timedelta

random.seed(42)

BASE_TIME    = datetime(2025, 3, 14, 0, 0, 0)
OUTPUT_FILE  = "data/web_logs.jsonl"

# ---------------------------------------------------------------------------
# IP pools
# ---------------------------------------------------------------------------
LEGIT_IPS = [str(ipaddress.IPv4Address(random.randint(0x01000000, 0xDFFFFFFF)))
             for _ in range(5000)]

# 900 attacker IPs mimicking a rotating proxy pool
ATTACKER_IPS = [str(ipaddress.IPv4Address(random.randint(0x01000000, 0xDFFFFFFF)))
                for _ in range(900)]

ENDPOINTS = ["/login", "/api/v1/auth", "/account/signin", "/user/login"]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "python-requests/2.31.0",
    "Go-http-client/1.1",
]

NORMAL_ENDPOINTS = [
    "/", "/home", "/about", "/products", "/search",
    "/cart", "/checkout", "/account", "/help", "/contact",
]


def ts(offset_seconds: int) -> str:
    return (BASE_TIME + timedelta(seconds=offset_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_logs():
    events = []

    # ------------------------------------------------------------------
    # Normal background traffic — ~10,000 events
    # ------------------------------------------------------------------
    for i in range(10000):
        events.append({
            "timestamp":   ts(random.randint(0, 86400)),
            "src_ip":      random.choice(LEGIT_IPS),
            "method":      random.choice(["GET", "POST"]),
            "path":        random.choice(NORMAL_ENDPOINTS),
            "status_code": random.choice([200, 200, 200, 301, 304, 404]),
            "user_agent":  random.choice(USER_AGENTS[:3]),
            "bytes":       random.randint(500, 50000),
            "__label__":   "benign",
        })

    # ------------------------------------------------------------------
    # Stage 1 — Credential stuffing (40,000 attempts, 900 IPs, 2-hour window)
    # ------------------------------------------------------------------
    stuffing_start = 3600  # 01:00 UTC
    for i in range(40000):
        offset = stuffing_start + random.randint(0, 7200)
        events.append({
            "timestamp":   ts(offset),
            "src_ip":      random.choice(ATTACKER_IPS),
            "method":      "POST",
            "path":        random.choice(ENDPOINTS),
            "status_code": random.choice([401, 401, 401, 403, 429, 200]),
            "user_agent":  random.choice(USER_AGENTS),
            "bytes":       random.randint(200, 800),
            "__label__":   "credential_stuffing",
        })

    # ------------------------------------------------------------------
    # Stage 2 — Fraud noise from hijacked customer accounts
    # ------------------------------------------------------------------
    for i in range(1200):
        events.append({
            "timestamp":   ts(random.randint(7200, 14400)),
            "src_ip":      random.choice(LEGIT_IPS[:200]),
            "method":      "POST",
            "path":        random.choice(["/checkout", "/cart/add", "/promo/redeem"]),
            "status_code": 200,
            "user_agent":  random.choice(USER_AGENTS[:3]),
            "bytes":       random.randint(400, 2000),
            "__label__":   "fraud_noise",
        })

    events.sort(key=lambda e: e["timestamp"])

    with open(OUTPUT_FILE, "w") as f:
        for event in events:
            f.write(json.dumps(event) + "\n")

    total     = len(events)
    malicious = sum(1 for e in events if e["__label__"] != "benign")
    print(f"[+] Web logs written to {OUTPUT_FILE}")
    print(f"    Total events : {total:,}")
    print(f"    Benign       : {total - malicious:,}")
    print(f"    Malicious    : {malicious:,}  ({malicious/total*100:.1f}%)")
    print(f"    Attacker IPs : {len(ATTACKER_IPS)} (rotating proxy pool)")


if __name__ == "__main__":
    write_logs()
