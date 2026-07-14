"""
DETECTION: CLD-006 — Cloud Recon Burst (Enumeration Threshold)
===============================================================
Rule shape  : Threshold — count distinct commands per identity per window
Data source : Cloud control plane audit logs
Severity    : MEDIUM

SIEM Query (pseudo-KQL / SPL):
  index=cloud_audit
  | where action IN (
      "iam:ListUsers", "iam:ListRoles", "iam:ListPolicies",
      "iam:GetAccountPasswordPolicy", "iam:SimulatePrincipalPolicy",
      "s3:ListBuckets", "s3:GetBucketAcl", "s3:GetBucketPolicy",
      "ec2:DescribeInstances", "ec2:DescribeSecurityGroups",
      "ec2:DescribeVpcs", "ec2:DescribeSubnets",
      "rds:DescribeDBInstances", "lambda:ListFunctions",
      "sts:GetCallerIdentity"
    )
  | bin timestamp span=10m
  | stats dc(action) AS distinct_commands BY actor, timestamp
  | where distinct_commands >= 5
  | fields actor, timestamp, distinct_commands

TUNING NOTES:
  - Threshold (5 distinct commands) is the key lever
  - Run a baseline: p99 of distinct enumeration commands in 10 min for any
    single identity during normal operations. Set threshold above that.
  - Exclude known security scanning tools and compliance automation accounts
  - Window (10 min) is narrow enough to catch rapid recon; widen to 30 min
    to catch slower, low-and-slow enumeration patterns

WHY THIS CATCHES FORAGER:
  No single enumeration command is suspicious. ListBuckets, DescribeInstances —
  these run in normal automation. The signal is the breadth: one identity,
  many different resource types, in rapid succession. That pattern describes
  an attacker mapping the environment after first access, not an application
  performing its designed function.
"""

import json
from datetime import datetime, timedelta
from collections import defaultdict

RECON_ACTIONS = {
    "iam:ListUsers", "iam:ListRoles", "iam:ListPolicies",
    "iam:GetAccountPasswordPolicy", "iam:SimulatePrincipalPolicy",
    "s3:ListBuckets", "s3:GetBucketAcl", "s3:GetBucketPolicy",
    "ec2:DescribeInstances", "ec2:DescribeSecurityGroups",
    "ec2:DescribeVpcs", "ec2:DescribeSubnets",
    "rds:DescribeDBInstances", "lambda:ListFunctions",
    "sts:GetCallerIdentity",
}

THRESHOLD_COMMANDS = 5     # distinct enumeration actions to trigger
WINDOW_MINUTES     = 10    # rolling window in minutes


def load_cloud_logs(path: str = "data/cloud_logs.jsonl") -> list[dict]:
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def parse_ts(ts: str) -> datetime:
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")


def run_detection(logs: list[dict]) -> list[dict]:
    """
    Sliding window: for each identity, collect all recon actions.
    If any 10-minute window contains >= THRESHOLD distinct commands, fire.
    """
    # Group recon events by actor
    actor_events: dict[str, list[tuple[datetime, str]]] = defaultdict(list)

    for event in logs:
        if event.get("action") in RECON_ACTIONS:
            actor_events[event["actor"]].append(
                (parse_ts(event["timestamp"]), event["action"])
            )

    alerts = []
    window = timedelta(minutes=WINDOW_MINUTES)

    for actor, events in actor_events.items():
        events.sort(key=lambda x: x[0])

        for i, (start_time, _) in enumerate(events):
            window_events  = [(t, a) for t, a in events if start_time <= t < start_time + window]
            distinct_cmds  = {a for _, a in window_events}

            if len(distinct_cmds) >= THRESHOLD_COMMANDS:
                alerts.append({
                    "rule_id":          "CLD-006",
                    "severity":         "MEDIUM",
                    "title":            "Cloud Recon Burst — Enumeration Threshold Exceeded",
                    "actor":            actor,
                    "window_start":     start_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "window_minutes":   WINDOW_MINUTES,
                    "distinct_commands": sorted(distinct_cmds),
                    "command_count":    len(distinct_cmds),
                    "analyst_action":   "Correlate with identity logs for this actor. "
                                        "Determine if this identity was recently reset or "
                                        "shows signs of compromise (IDNT-002). "
                                        "Recon burst + identity takeover = active intrusion.",
                })
                break  # one alert per actor per detection run

    return alerts


if __name__ == "__main__":
    logs   = load_cloud_logs()
    alerts = run_detection(logs)
    print(f"\n[CLD-006] Recon Burst Detection")
    print(f"  Logs analysed : {len(logs):,}")
    print(f"  Alerts fired  : {len(alerts)}\n")
    for alert in alerts:
        print(f"  ALERT  → {alert['actor']}")
        print(f"    Window     : {alert['window_minutes']} minutes from {alert['window_start']}")
        print(f"    Commands   : {alert['command_count']} distinct — {', '.join(alert['distinct_commands'])}")
        print(f"    Action     : {alert['analyst_action']}\n")
