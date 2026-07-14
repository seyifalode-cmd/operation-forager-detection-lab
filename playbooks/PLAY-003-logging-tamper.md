# IR PLAYBOOK: PLAY-003 — Cloud Logging Disabled (CLD-005)

**Triggers:** CLD-005 alert — cloudtrail:StopLogging or cloudtrail:DeleteTrail  
**Severity:** CRITICAL  
**Target SLA:** Re-enable logging within 5 minutes. Assume active incident.

---

## Immediate Response (0–5 minutes)

```
1. RE-ENABLE CLOUDTRAIL IMMEDIATELY
   aws cloudtrail start-logging --name [trail-name] --region [region]

2. SUSPEND the actor identity that disabled logging
   aws iam put-user-policy --user-name [actor] \
     --policy-name DenyAll \
     --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'

3. SNAPSHOT current state of all S3 buckets accessible to the actor
   (establish baseline for exfiltration comparison)

4. PRESERVE the StopLogging event in CloudTrail before it could rotate
   Export to a separate, attacker-inaccessible location
```

## Gap Analysis (5–30 minutes)

```
The period between StopLogging and re-enabling is a blind spot.
Use alternative data sources to reconstruct activity during the gap:

1. S3 server access logs (separate from CloudTrail — may still be active)
   - Compare object access counts before and after the gap
   - Large GET volumes = presumed exfiltration

2. VPC Flow Logs (separate from CloudTrail)
   - Look for large egress bytes from compute instances to external IPs

3. AWS Cost Explorer
   - Unexpected data transfer costs in the gap window

4. GuardDuty (if enabled and not separately disabled)
   - Findings may still have fired during the gap
```

## Scope Determination

```
Assume the attacker exfiltrated data during the gap until proven otherwise.
Determine what was accessible:
  - What S3 buckets did the actor or their assumed role have read access to?
  - What data classifications are in those buckets?
  - Does this trigger breach notification requirements?
```

## Escalation

```
If data exfiltration is confirmed or cannot be ruled out:
  → Escalate to Legal and Privacy team within 1 hour
  → Assess breach notification obligations (PIPEDA, GDPR if applicable)
  → Preserve all evidence under legal hold
```
