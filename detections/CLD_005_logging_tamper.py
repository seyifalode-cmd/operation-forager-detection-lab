"""
DETECTION: CLD-005 — Cloud Audit Logging Disabled
===================================================
Rule shape  : Single-event — no tuning, zero tolerance
Data source : Cloud control plane audit logs
Severity    : CRITICAL

SIEM Query (pseudo-KQL / SPL):
  index=cloud_audit
  | where action IN ("cloudtrail:StopLogging", "cloudtrail:DeleteTrail",
                     "cloudtrail:PutEventSelectors",
                     "config:StopConfigurationRecorder",
                     "guardduty:DeleteDetector")
  | fields timestamp, actor, action, resource, src_ip

TUNING NOTES:
  NONE. This rule is never tuned down.

  There is no legitimate operational reason to disable the cloud security
  recorder during normal business activity. This is among the loudest
  signals an attacker can produce. Even a pentest team should have a
  pre-approved change window documented before this action is taken.
  If this fires outside a documented change window: treat as active incident.

WHY THIS CATCHES FORAGER:
  The attacker disables logging before exfiltration to prevent subsequent
  API calls from appearing in the audit trail. The irony: disabling logging
  IS an API call that gets logged — it is the last event before the silence.
  Absence of subsequent log events is itself evidence of the evasion.
"""

import json

EVASION_ACTIONS = {
    "cloudtrail:StopLogging",
    "cloudtrail:DeleteTrail",
    "cloudtrail:PutEventSelectors",
    "config:StopConfigurationRecorder",
    "guardduty:DeleteDetector",
    "guardduty:DisassociateFromMasterAccount",
}


def load_cloud_logs(path: str = "data/cloud_logs.jsonl") -> list[dict]:
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def run_detection(logs: list[dict]) -> list[dict]:
    """Fire on any attempt to disable cloud audit logging. No threshold. No exceptions."""
    alerts = []

    for event in logs:
        if event.get("action") in EVASION_ACTIONS:
            alerts.append({
                "rule_id":       "CLD-005",
                "severity":      "CRITICAL",
                "title":         "Defence Evasion — Cloud Audit Logging Disabled",
                "timestamp":     event["timestamp"],
                "actor":         event["actor"],
                "action":        event["action"],
                "resource":      event.get("resource", "unknown"),
                "src_ip":        event.get("src_ip", "unknown"),
                "analyst_action": "IMMEDIATE RESPONSE REQUIRED. "
                                  "Re-enable logging. Isolate the actor identity. "
                                  "Assume all activity after this timestamp is unlogged. "
                                  "Initiate IR playbook: PLAY-003.",
            })

    return alerts


if __name__ == "__main__":
    logs   = load_cloud_logs()
    alerts = run_detection(logs)
    print(f"\n[CLD-005] Logging Tamper Detection")
    print(f"  Logs analysed : {len(logs):,}")
    print(f"  Alerts fired  : {len(alerts)}\n")
    for alert in alerts:
        print(f"  ALERT  → {alert['action']}")
        print(f"    Actor     : {alert['actor']}")
        print(f"    Resource  : {alert['resource']}")
        print(f"    Timestamp : {alert['timestamp']}")
        print(f"    Action    : {alert['analyst_action']}\n")
