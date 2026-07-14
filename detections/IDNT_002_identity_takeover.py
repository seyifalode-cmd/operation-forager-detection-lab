"""
DETECTION: IDNT-002 — Identity Takeover via MFA Reset and Device Registration
==============================================================================
Rule shape  : Correlation (two events, same actor, short time window)
Data source : Cloud identity audit logs
Severity    : CRITICAL

SIEM Query (pseudo-KQL / SPL):
  index=identity_audit
  | where event_type IN ("mfa_reset", "mfa_device_registered")
  | stats
      count_where(event_type == "mfa_reset")        AS resets,
      min_where(timestamp, event_type == "mfa_reset") AS reset_time,
      count_where(event_type == "mfa_device_registered") AS registrations,
      min_where(timestamp, event_type == "mfa_device_registered") AS reg_time
    BY target_user
  | where resets >= 1 AND registrations >= 1
  | where (reg_time - reset_time) <= 3600          -- within 60 minutes
  | where reg_time > reset_time                    -- registration AFTER reset
  | fields target_user, reset_time, reg_time, (reg_time - reset_time) AS gap_seconds

TUNING NOTES:
  - Window (3600s) reduces false positives vs. a wider daily window
  - "reg_time > reset_time" eliminates pre-existing device registrations
  - Exclude known IT provisioning accounts from actor field if needed
  - Baseline: ~25 legitimate resets per day in a 200-user org; none should
    trigger this rule if devices were already registered before the reset

WHY THIS CATCHES FORAGER:
  A helpdesk MFA reset alone is normal. A device registration alone is normal.
  The attacker's tell is both events on the same account in tight sequence —
  reset the factor, then immediately enrol an attacker-controlled device.
  No legitimate user does this; they already have a registered device.
"""

import json
from datetime import datetime
from pathlib import Path


CORRELATION_WINDOW_SECONDS = 3600  # 60 minutes


def load_identity_logs(path: str = "data/identity_logs.jsonl") -> list[dict]:
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def parse_ts(ts: str) -> datetime:
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")


def run_detection(logs: list[dict]) -> list[dict]:
    """
    Correlate mfa_reset → mfa_device_registered on the same target_user
    within the correlation window. Returns one alert per matching user.
    """
    resets        = {}  # target_user → earliest reset timestamp
    registrations = {}  # target_user → earliest registration timestamp

    for event in logs:
        user = event.get("target_user")
        if not user:
            continue

        if event["event_type"] == "mfa_reset":
            t = parse_ts(event["timestamp"])
            if user not in resets or t < resets[user]:
                resets[user] = t

        elif event["event_type"] == "mfa_device_registered":
            t = parse_ts(event["timestamp"])
            if user not in registrations or t < registrations[user]:
                registrations[user] = t

    alerts = []
    for user in resets:
        if user not in registrations:
            continue
        reset_time = resets[user]
        reg_time   = registrations[user]
        gap        = (reg_time - reset_time).total_seconds()

        if reg_time > reset_time and gap <= CORRELATION_WINDOW_SECONDS:
            alerts.append({
                "rule_id":          "IDNT-002",
                "severity":         "CRITICAL",
                "title":            "Identity Takeover — MFA Reset Followed by Device Registration",
                "target_user":      user,
                "mfa_reset_time":   reset_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "device_reg_time":  reg_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "gap_minutes":      round(gap / 60, 1),
                "analyst_action":   "Verify reset was initiated by a known helpdesk ticket. "
                                    "Check src_ip of device registration — Tor/VPN = confirmed compromise.",
            })

    return alerts


if __name__ == "__main__":
    logs   = load_identity_logs()
    alerts = run_detection(logs)
    print(f"\n[IDNT-002] Identity Takeover Detection")
    print(f"  Logs analysed : {len(logs):,}")
    print(f"  Alerts fired  : {len(alerts)}\n")
    for alert in alerts:
        print(f"  ALERT  → {alert['target_user']}")
        print(f"    MFA reset    : {alert['mfa_reset_time']}")
        print(f"    Device reg   : {alert['device_reg_time']}")
        print(f"    Gap          : {alert['gap_minutes']} minutes")
        print(f"    Action       : {alert['analyst_action']}\n")
