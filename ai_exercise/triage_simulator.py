"""
OPERATION FORAGER — AI Triage Simulator & Human Validation Exercise
====================================================================
Simulates an AI-augmented SOC triage pipeline that performs first-pass
analysis on three alerts — and gets all three wrong in the specific ways
real AI systems fail.

The exercise:
  Read each case. Identify WHAT the AI got wrong and WHY. Write the single
  specific check the AI skipped that would flip the verdict.

  Good feedback is never "the AI was wrong."
  Good feedback is: "The AI did not check X. If it had, the verdict changes."
  That is the human-in-the-loop discipline modern SOC pipelines depend on.

Usage:
  python ai_exercise/triage_simulator.py

Three classic AI triage failure modes demonstrated:
  Case 1 — Trusting a control signal without verifying the audit trail
  Case 2 — Pattern-matching to a known-benign category without checking context
  Case 3 — Misreading absence of evidence as evidence of absence
"""

import json
import time


def simulate_ai_analysis(case: dict, delay: float = 0.8) -> str:
    """Simulate AI processing with a brief pause for effect."""
    time.sleep(delay)
    return case["ai_verdict"]


CASES = [
    {
        "id": "CASE-001",
        "alert": {
            "rule_id":    "IDNT-002",
            "title":      "Identity Takeover — MFA Reset + Device Registration",
            "actor":      "user_0042@corp.example.com",
            "mfa_reset":  "2025-03-14T02:00:00Z",
            "device_reg": "2025-03-14T02:29:00Z",
            "src_ip":     "185.220.101.47",
            "gap_minutes": 29,
        },
        "ai_verdict": "BENIGN — MFA challenge was satisfied at sign-in. "
                      "Authentication completed successfully. No further action required.",
        "ai_reasoning": [
            "MFA event present in sign-in log",
            "Authentication result = success",
            "No prior alerts on this account",
        ],
        "what_ai_missed": "MFA passing does not prove identity — it proves the attacker controls "
                          "the registered device. The AI checked the sign-in result but never "
                          "looked at the audit log one step earlier: who reset the MFA factor "
                          "and when. The reset (02:00) and device registration (02:29) are in "
                          "the audit trail. The AI trusted a downstream signal without verifying "
                          "the upstream audit trail that would have invalidated it.",
        "correct_verdict": "CONFIRMED COMPROMISE — MFA reset by helpdesk at 02:00, new device "
                           "registered at 02:29 from Tor exit node 185.220.101.47. The attacker "
                           "reset the factor, enrolled their own device, then satisfied their "
                           "own MFA challenge. The passing MFA is evidence of the attack, not "
                           "evidence against it.",
        "fix": "Add audit log correlation: flag any sign-in where the MFA device was registered "
               "within 60 minutes of a helpdesk-initiated MFA reset on the same account.",
    },
    {
        "id": "CASE-002",
        "alert": {
            "rule_id":   "CLD-004",
            "title":     "Persistence — Access Key Created on Dormant Service Account",
            "actor":     "user_0042@corp.example.com",
            "target":    "svc-legacy-reporting",
            "timestamp": "2025-03-14T02:42:00Z",
            "src_ip":    "185.220.101.47",
        },
        "ai_verdict": "BENIGN — Access key creation matches routine key rotation pattern. "
                      "Service account key management is expected operational activity.",
        "ai_reasoning": [
            "iam:CreateAccessKey is a common operational action",
            "Action matches 'key rotation' pattern in training data",
            "No anomaly score threshold exceeded",
        ],
        "what_ai_missed": "Key rotation means creating a new key AND deleting the old one, "
                          "within a short window, by an automation tool. None of those conditions "
                          "are met here. The AI pattern-matched to 'key rotation' because "
                          "CreateAccessKey was present — but never checked for the corresponding "
                          "DeleteAccessKey, never checked whether the creating identity is an "
                          "automation account, and never checked whether the target account was "
                          "dormant. The account has zero prior API activity. There is no rotation "
                          "in progress.",
        "correct_verdict": "CONFIRMED PERSISTENCE — Attacker creating a permanent backdoor key on "
                           "a dormant, over-privileged service account. No DeleteAccessKey event "
                           "follows. The creating identity (user_0042) is a compromised human "
                           "account, not an automation tool. This is the classic persistence "
                           "technique: gain access via a compromised human, maintain access via "
                           "a service account key that survives the human's password reset.",
        "fix": "Key rotation detection requires CreateAccessKey AND DeleteAccessKey within 5 "
               "minutes by the same automation principal on the same account. CreateAccessKey "
               "alone on a dormant account by a human principal is always suspicious.",
    },
    {
        "id": "CASE-003",
        "alert": {
            "rule_id":   "CLD-005",
            "title":     "Defence Evasion — CloudTrail Logging Disabled",
            "actor":     "user_0042@corp.example.com",
            "action":    "cloudtrail:StopLogging",
            "timestamp": "2025-03-14T02:45:00Z",
            "src_ip":    "185.220.101.47",
        },
        "ai_verdict": "LOW PRIORITY — No suspicious activity detected in logs following the "
                      "StopLogging event. Situation appears stable. Monitor and reassess.",
        "ai_reasoning": [
            "No malicious events found after the StopLogging timestamp",
            "Alert volume did not increase post-event",
            "No exfiltration signatures detected",
        ],
        "what_ai_missed": "The AI looked for events after logging stopped and found none — and "
                          "concluded this was reassuring. It is the opposite. The events are "
                          "missing BECAUSE the attacker turned the logging off. The silence IS "
                          "the attack. Absence of evidence is not evidence of absence. The AI "
                          "was searching in the dark with the lights turned off and reported "
                          "that it could not see anything.",
        "correct_verdict": "CRITICAL — Active attacker disabling the security recorder immediately "
                           "before exfiltration. The gap in log data after 02:45 is forensic "
                           "evidence of the evasion, not evidence of calm. Re-enable logging "
                           "immediately, assume bulk exfiltration occurred in the gap, initiate "
                           "IR playbook, and preserve all available evidence before it rotates.",
        "fix": "Treat log gaps following a StopLogging event as presumed malicious activity. "
               "After re-enabling logging, compare S3 access patterns and network egress metrics "
               "from the gap window to establish what was taken.",
    },
]


def run_exercise():
    print("\n" + "=" * 65)
    print("  OPERATION FORAGER — AI TRIAGE VALIDATION EXERCISE")
    print("=" * 65)
    print("""
  The automated triage pipeline has reviewed three alerts and
  produced verdicts. All three verdicts are wrong.

  Your job: identify what the AI missed and what the correct
  verdict is. The answers follow each case.
""")

    for case in CASES:
        alert = case["alert"]
        print(f"\n{'─' * 65}")
        print(f"  {case['id']}  |  {alert['title']}")
        print(f"{'─' * 65}")
        print(f"  Actor     : {alert['actor']}")
        print(f"  Timestamp : {alert.get('timestamp', alert.get('mfa_reset', 'N/A'))}")
        print(f"  Source IP : {alert.get('src_ip', 'N/A')}")

        print(f"\n  [AI PIPELINE] Analysing alert...", end="", flush=True)
        verdict = simulate_ai_analysis(case)
        print(f"\n\n  AI VERDICT   : {verdict}")
        print(f"\n  AI reasoning :")
        for r in case["ai_reasoning"]:
            print(f"    - {r}")

        print(f"\n  ── WHAT THE AI MISSED ──────────────────────────────────")
        print(f"  {case['what_ai_missed']}")

        print(f"\n  ── CORRECT VERDICT ─────────────────────────────────────")
        print(f"  {case['correct_verdict']}")

        print(f"\n  ── THE FIX (one specific check) ────────────────────────")
        print(f"  {case['fix']}")

    print(f"\n{'=' * 65}")
    print("  CORE LESSON")
    print(f"{'=' * 65}")
    print("""
  AI triage systems fail in predictable ways:

  1. They trust downstream signals without verifying upstream context
  2. They pattern-match to category labels without checking conditions
  3. They treat absence of evidence as evidence of absence

  Good human-in-the-loop feedback is never "the AI was wrong."
  It is specific and buildable: name the check it skipped and the
  single change that would flip the verdict.

  That precision is the skill these systems depend on.
""")


if __name__ == "__main__":
    run_exercise()
