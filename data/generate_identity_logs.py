"""
OPERATION FORAGER — Identity Log Generator
============================================
Generates synthetic cloud identity audit and sign-in logs simulating
Stages 3 & 4 of the FORAGER intrusion.

Stage 3 — Helpdesk vishing: attacker phones IT, social-engineers them into
           resetting an employee's MFA factor. One audit event: mfa_reset.
Stage 4 — MFA-satisfied sign-in: attacker logs in as the employee 29 minutes
           after resetting the factor, and registers their own device.
           Two audit events: mfa_device_registered + successful sign-in.

Design detail: the attack is 2 malicious events hiding inside 27 legitimate
audit records — the needle-in-a-haystack ratio of real security operations.

Output: data/identity_logs.jsonl
"""

import json
import random
from datetime import datetime, timedelta

random.seed(42)

BASE_TIME   = datetime(2025, 3, 14, 0, 0, 0)
OUTPUT_FILE = "data/identity_logs.jsonl"

EMPLOYEES = [f"user_{i:04d}@corp.example.com" for i in range(1, 201)]
ATTACKER_VICTIM = "user_0042@corp.example.com"
ATTACKER_IP     = "185.220.101.47"  # Tor exit node
HELPDESK_IP     = "10.0.1.15"

DEVICE_IDS = [f"device-{random.randint(100000, 999999)}" for _ in range(300)]
LOCATIONS  = ["Toronto, CA", "Vancouver, CA", "Montreal, CA", "Ottawa, CA",
              "Calgary, CA", "New York, US", "Chicago, US"]


def ts(offset_seconds: int) -> str:
    return (BASE_TIME + timedelta(seconds=offset_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_logs():
    events = []

    # ------------------------------------------------------------------
    # Normal identity audit events — password changes, MFA resets,
    # device registrations by legitimate users
    # ------------------------------------------------------------------
    for _ in range(25):
        user = random.choice([u for u in EMPLOYEES if u != ATTACKER_VICTIM])
        reset_offset = random.randint(0, 86400)
        events.append({
            "timestamp":   ts(reset_offset),
            "event_type":  "mfa_reset",
            "actor":       "helpdesk@corp.example.com",
            "target_user": user,
            "src_ip":      HELPDESK_IP,
            "result":      "success",
            "reason":      "user_request",
            "__label__":   "benign",
        })
        # Legitimate device registration after MFA reset (same day, random gap)
        if random.random() > 0.4:
            events.append({
                "timestamp":   ts(reset_offset + random.randint(600, 7200)),
                "event_type":  "mfa_device_registered",
                "actor":       user,
                "target_user": user,
                "device_id":   random.choice(DEVICE_IDS),
                "src_ip":      f"192.168.{random.randint(1,10)}.{random.randint(1,254)}",
                "result":      "success",
                "__label__":   "benign",
            })

    # Normal sign-ins
    for _ in range(500):
        user = random.choice(EMPLOYEES)
        events.append({
            "timestamp":   ts(random.randint(28800, 72000)),
            "event_type":  "sign_in",
            "actor":       user,
            "src_ip":      f"192.168.{random.randint(1,10)}.{random.randint(1,254)}",
            "location":    random.choice(LOCATIONS),
            "mfa_method":  random.choice(["authenticator_app", "sms", "hardware_token"]),
            "result":      "success",
            "device_id":   random.choice(DEVICE_IDS),
            "__label__":   "benign",
        })

    # ------------------------------------------------------------------
    # Stage 3 — Attacker social-engineers helpdesk into resetting victim MFA
    # Attack begins at 02:00 UTC (7200s)
    # ------------------------------------------------------------------
    VISHING_OFFSET = 7200
    events.append({
        "timestamp":   ts(VISHING_OFFSET),
        "event_type":  "mfa_reset",
        "actor":       "helpdesk@corp.example.com",
        "target_user": ATTACKER_VICTIM,
        "src_ip":      HELPDESK_IP,
        "result":      "success",
        "reason":      "user_request",
        "note":        "Initiated via phone call — identity not verified beyond name",
        "__label__":   "identity_takeover_reset",
    })

    # Stage 3b — Attacker immediately registers their own device (29 min later)
    DEVICE_REG_OFFSET = VISHING_OFFSET + (29 * 60)
    ATTACKER_DEVICE   = "device-ATTACKER-001"
    events.append({
        "timestamp":   ts(DEVICE_REG_OFFSET),
        "event_type":  "mfa_device_registered",
        "actor":       ATTACKER_VICTIM,
        "target_user": ATTACKER_VICTIM,
        "device_id":   ATTACKER_DEVICE,
        "src_ip":      ATTACKER_IP,
        "result":      "success",
        "__label__":   "identity_takeover_device_reg",
    })

    # ------------------------------------------------------------------
    # Stage 4 — Attacker signs in with attacker-controlled MFA (2 min later)
    # ------------------------------------------------------------------
    events.append({
        "timestamp":   ts(DEVICE_REG_OFFSET + 120),
        "event_type":  "sign_in",
        "actor":       ATTACKER_VICTIM,
        "src_ip":      ATTACKER_IP,
        "location":    "Frankfurt, DE",
        "mfa_method":  "authenticator_app",
        "result":      "success",
        "device_id":   ATTACKER_DEVICE,
        "note":        "MFA satisfied — attacker controls the registered device",
        "__label__":   "attacker_signin",
    })

    events.sort(key=lambda e: e["timestamp"])

    with open(OUTPUT_FILE, "w") as f:
        for event in events:
            f.write(json.dumps(event) + "\n")

    total     = len(events)
    malicious = sum(1 for e in events if "benign" not in e["__label__"])
    print(f"[+] Identity logs written to {OUTPUT_FILE}")
    print(f"    Total events : {total:,}")
    print(f"    Benign       : {total - malicious:,}")
    print(f"    Malicious    : {malicious:,}  (buried in {total - malicious:,} legitimate records)")
    print(f"    Victim       : {ATTACKER_VICTIM}")
    print(f"    Attack IPs   : {ATTACKER_IP} (Tor exit node)")


if __name__ == "__main__":
    write_logs()
