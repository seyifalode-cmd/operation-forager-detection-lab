"""
OPERATION FORAGER — Cloud Control Plane Log Generator
=======================================================
Generates synthetic cloud audit logs simulating Stages 5–8 of the FORAGER
intrusion once the attacker is inside the environment.

Stage 5 — Cloud pivot & recon: attacker enumerates IAM, S3, EC2, RDS, Lambda
           to map what the compromised identity can reach.
Stage 6 — Persistence: attacker creates a permanent access key on a dormant,
           over-privileged service account.
Stage 7 — Defence evasion: attacker disables CloudTrail logging to hide
           subsequent activity.
Stage 8 — Exfiltration: attacker bulk-reads customer records from S3.

Output: data/cloud_logs.jsonl
"""

import json
import random
from datetime import datetime, timedelta

random.seed(42)

BASE_TIME   = datetime(2025, 3, 14, 0, 0, 0)
OUTPUT_FILE = "data/cloud_logs.jsonl"

ATTACKER_VICTIM  = "user_0042@corp.example.com"
ATTACKER_IP      = "185.220.101.47"
DORMANT_ACCOUNT  = "svc-legacy-reporting"
NORMAL_USERS     = [f"svc-{name}" for name in
                    ["web-app", "data-pipeline", "monitoring", "billing", "auth"]]
NORMAL_USERS    += [f"user_{i:04d}@corp.example.com" for i in range(1, 50)]

CLOUD_ACTIONS = {
    "recon": [
        "iam:ListUsers", "iam:ListRoles", "iam:ListPolicies",
        "s3:ListBuckets", "ec2:DescribeInstances", "rds:DescribeDBInstances",
        "lambda:ListFunctions", "iam:GetAccountPasswordPolicy",
    ],
    "persistence": ["iam:CreateAccessKey"],
    "evasion":     ["cloudtrail:StopLogging", "cloudtrail:DeleteTrail"],
    "exfiltration": ["s3:GetObject", "s3:ListObjectsV2"],
    "normal": [
        "s3:PutObject", "s3:GetObject", "ec2:DescribeInstances",
        "lambda:InvokeFunction", "rds:DescribeDBInstances",
        "iam:GetUser", "s3:ListBuckets", "cloudwatch:PutMetricData",
    ],
}


def ts(offset_seconds: int) -> str:
    return (BASE_TIME + timedelta(seconds=offset_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_logs():
    events = []

    # ------------------------------------------------------------------
    # Normal cloud API activity — routine service calls
    # ------------------------------------------------------------------
    for _ in range(800):
        user = random.choice(NORMAL_USERS)
        events.append({
            "timestamp":  ts(random.randint(0, 86400)),
            "event_type": "api_call",
            "actor":      user,
            "action":     random.choice(CLOUD_ACTIONS["normal"]),
            "src_ip":     f"10.0.{random.randint(0,10)}.{random.randint(1,254)}",
            "resource":   f"arn:aws:s3:::bucket-{random.randint(1,5)}",
            "result":     "success",
            "__label__":  "benign",
        })

    # ------------------------------------------------------------------
    # Stage 5 — Recon burst: 5 distinct enumeration commands, rapid succession
    # Attacker maps the environment after gaining access (02:32 UTC)
    # ------------------------------------------------------------------
    RECON_START = 9120  # 02:32 UTC
    for i, action in enumerate(CLOUD_ACTIONS["recon"][:5]):
        events.append({
            "timestamp":  ts(RECON_START + (i * 45)),
            "event_type": "api_call",
            "actor":      ATTACKER_VICTIM,
            "action":     action,
            "src_ip":     ATTACKER_IP,
            "resource":   "*",
            "result":     "success",
            "__label__":  "recon",
        })

    # ------------------------------------------------------------------
    # Stage 6 — Persistence: access key on dormant service account
    # Dormant = no API calls in the logs before this event
    # ------------------------------------------------------------------
    PERSIST_OFFSET = RECON_START + 600
    events.append({
        "timestamp":  ts(PERSIST_OFFSET),
        "event_type": "api_call",
        "actor":      ATTACKER_VICTIM,
        "action":     "iam:CreateAccessKey",
        "src_ip":     ATTACKER_IP,
        "resource":   f"arn:aws:iam::123456789012:user/{DORMANT_ACCOUNT}",
        "target_user": DORMANT_ACCOUNT,
        "result":     "success",
        "note":       "Permanent key created on dormant service account — no prior activity",
        "__label__":  "persistence",
    })

    # ------------------------------------------------------------------
    # Stage 7 — Defence evasion: disable CloudTrail
    # ------------------------------------------------------------------
    EVASION_OFFSET = PERSIST_OFFSET + 180
    events.append({
        "timestamp":  ts(EVASION_OFFSET),
        "event_type": "api_call",
        "actor":      ATTACKER_VICTIM,
        "action":     "cloudtrail:StopLogging",
        "src_ip":     ATTACKER_IP,
        "resource":   "arn:aws:cloudtrail:us-east-1:123456789012:trail/corp-audit-trail",
        "result":     "success",
        "note":       "Logging disabled — subsequent activity will not be recorded",
        "__label__":  "logging_tamper",
    })

    # ------------------------------------------------------------------
    # Stage 8 — Exfiltration: bulk S3 read of customer records
    # (occurs after logging disabled — these events exist as a gap in prod)
    # ------------------------------------------------------------------
    EXFIL_OFFSET = EVASION_OFFSET + 120
    for i in range(50):
        events.append({
            "timestamp":  ts(EXFIL_OFFSET + (i * 3)),
            "event_type": "api_call",
            "actor":      DORMANT_ACCOUNT,
            "action":     "s3:GetObject",
            "src_ip":     ATTACKER_IP,
            "resource":   f"arn:aws:s3:::customer-records/batch_{i:04d}.csv",
            "result":     "success",
            "__label__":  "exfiltration",
        })

    events.sort(key=lambda e: e["timestamp"])

    with open(OUTPUT_FILE, "w") as f:
        for event in events:
            f.write(json.dumps(event) + "\n")

    total     = len(events)
    malicious = sum(1 for e in events if e["__label__"] != "benign")
    print(f"[+] Cloud logs written to {OUTPUT_FILE}")
    print(f"    Total events    : {total:,}")
    print(f"    Benign          : {total - malicious:,}")
    print(f"    Malicious       : {malicious:,}")
    print(f"    Dormant account : {DORMANT_ACCOUNT}")


if __name__ == "__main__":
    write_logs()
