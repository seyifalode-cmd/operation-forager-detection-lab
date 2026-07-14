"""
DETECTION: CLD-004 — Permanent Access Key Created on Dormant Service Account
=============================================================================
Rule shape  : Single-event with condition on target account activity history
Data source : Cloud control plane audit logs
Severity    : HIGH

SIEM Query (pseudo-KQL / SPL):
  index=cloud_audit
  | where action == "iam:CreateAccessKey"
  | lookup dormant_accounts ON target_user
  | where is_dormant == true
  | fields timestamp, actor, target_user, src_ip

  -- Dormant = no API calls in the past 30 days
  -- Build the dormant_accounts lookup daily from the same audit log index

TUNING NOTES:
  - "Dormant" threshold (30 days) should be tuned to org baseline
  - Exclude automated key rotation workflows that create AND delete in <5 min
  - Legitimate key creation on active accounts is normal; condition is the
    dormant target — that combination has no benign explanation
  - If full 30-day history is unavailable, any account with zero prior events
    in the available window is sufficient for high-confidence alerting

WHY THIS CATCHES FORAGER:
  The attacker needs durable access that survives password resets. Creating a
  permanent access key on a dormant, over-privileged service account is a
  classic persistence technique. The key signals: (1) the creating identity is
  the compromised employee, not an automation tool; (2) the target account has
  been dormant — no legitimate reason to activate it now.
"""

import json
from pathlib import Path


def load_cloud_logs(path: str = "data/cloud_logs.jsonl") -> list[dict]:
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def get_active_accounts(logs: list[dict]) -> set[str]:
    """Accounts with ANY prior API activity are not dormant."""
    return {e["actor"] for e in logs if e["event_type"] == "api_call"}


def run_detection(logs: list[dict]) -> list[dict]:
    """
    Fire on iam:CreateAccessKey where the target_user has no prior API activity
    in the log window (proxy for dormant account).
    """
    active_accounts = get_active_accounts(logs)
    alerts = []

    for event in logs:
        if event.get("action") != "iam:CreateAccessKey":
            continue

        target = event.get("target_user", "")
        if not target:
            continue

        # A dormant account has no prior API activity
        if target not in active_accounts:
            alerts.append({
                "rule_id":       "CLD-004",
                "severity":      "HIGH",
                "title":         "Persistence — Access Key Created on Dormant Service Account",
                "timestamp":     event["timestamp"],
                "actor":         event["actor"],
                "target_user":   target,
                "src_ip":        event.get("src_ip", "unknown"),
                "analyst_action": "Immediately disable the newly created access key. "
                                  "Determine why the dormant account was targeted. "
                                  "Treat the creating identity as compromised.",
            })

    return alerts


if __name__ == "__main__":
    logs   = load_cloud_logs()
    alerts = run_detection(logs)
    print(f"\n[CLD-004] Access Key Persistence Detection")
    print(f"  Logs analysed : {len(logs):,}")
    print(f"  Alerts fired  : {len(alerts)}\n")
    for alert in alerts:
        print(f"  ALERT  → Key created by {alert['actor']}")
        print(f"    Target account : {alert['target_user']} (DORMANT)")
        print(f"    Timestamp      : {alert['timestamp']}")
        print(f"    Source IP      : {alert['src_ip']}")
        print(f"    Action         : {alert['analyst_action']}\n")
