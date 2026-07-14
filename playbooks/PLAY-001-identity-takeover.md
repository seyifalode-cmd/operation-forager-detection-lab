# IR PLAYBOOK: PLAY-001 — Identity Takeover (IDNT-002)

**Triggers:** IDNT-002 alert — MFA reset followed by device registration within 60 minutes  
**Severity:** CRITICAL  
**Target SLA:** Contain within 15 minutes of alert

---

## Immediate Response (0–5 minutes)

```
1. SUSPEND the target user account immediately
   Entra admin center → Users → [target] → Block sign-in: Yes

2. REVOKE all active sessions
   Entra admin center → Users → [target] → Revoke sessions

3. IDENTIFY and REMOVE the attacker-registered device
   Entra admin center → Devices → filter by target user → Delete attacker device

4. RESET all MFA factors on the compromised account
   Do NOT restore to the pre-attack state — verify new enrollment with the real user
```

## Investigation (5–30 minutes)

```
1. Pull all sign-in logs for the target identity in the past 24 hours
   - Were there successful sign-ins from foreign IPs?
   - What applications were accessed?

2. Pull all cloud audit logs for the target identity
   - Were any IAM actions taken? (CreateAccessKey, AttachPolicy)
   - Were any resources enumerated?

3. Cross-correlate with cloud logs
   - Run CLD-006 for this actor — was there a recon burst?
   - Run CLD-004 for this actor — was a persistence key created?
   - Run CLD-005 — was logging disabled?

4. Check for lateral movement
   - Did the attacker access any additional accounts or roles?
   - Were any S3 objects accessed?
```

## Evidence Preservation

```
- Export Entra sign-in logs for the target identity (last 7 days)
- Export CloudTrail events for the target identity (last 24 hours)
- Screenshot the attacker device registration record before deletion
- Preserve helpdesk ticket that authorised the original MFA reset
```

## Recovery

```
1. Verify real user identity via out-of-band channel (phone call, not email)
2. Re-enrol MFA factors with the verified user present
3. Restore account access
4. Notify the user of what occurred and what the attacker may have accessed
5. File internal incident report within 24 hours
```
