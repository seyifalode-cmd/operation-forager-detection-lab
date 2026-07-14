# THREAT ACTOR: FORAGER

**Classification:** Financially motivated / access broker  
**TTPs:** Social engineering, identity abuse, cloud pivot — no malware

---

## Actor Summary

FORAGER is a composite threat actor modelled on modern identity-focused intrusion groups
(analogues: Scattered Spider, Lapsus$, UNC3944). The defining characteristic is the
complete absence of malware. FORAGER relies entirely on:

1. Stolen credentials from breach datasets
2. Social engineering of helpdesk personnel
3. Abuse of legitimate cloud APIs with legitimate credentials

There are no file hashes to block. No fixed C2 domains. No malicious binaries.
Every action FORAGER takes could, in isolation, be performed by a legitimate user.
The only way to catch FORAGER is to detect **what they do**, not **what tool they use**.

---

## Attack Chain (8 Stages)

| Stage | Technique | MITRE ATT&CK |
|---|---|---|
| 1 | Credential stuffing — rotating proxy pool, 900 IPs | T1110.004 Credential Stuffing |
| 2 | Fraud noise — hijacked customer accounts used as decoy | T1078 Valid Accounts |
| 3 | Helpdesk vishing — MFA reset via social engineering | T1656 Impersonation |
| 4 | MFA-satisfied sign-in — attacker controls enrolled device | T1621 MFA Request Generation |
| 5 | Cloud recon — enumerate IAM, S3, EC2, RDS, Lambda | T1580 Cloud Infrastructure Discovery |
| 6 | Persistence — permanent access key on dormant service account | T1098.001 Additional Cloud Credentials |
| 7 | Defence evasion — disable CloudTrail | T1562.008 Disable Cloud Logs |
| 8 | Exfiltration — bulk S3 read of customer records | T1530 Data from Cloud Storage |

---

## Why Behavioural Detection Is the Only Answer

FORAGER deliberately avoids every signature-based detection control:

- **No malware** → antivirus and EDR signatures are useless
- **No fixed IPs** → IP blocklists are useless (rotating proxy pool)
- **No file hashes** → hash-based blocking is useless
- **Valid MFA** → MFA passing is evidence of the attack, not against it

The only detections that work are behavioural:
- *What sequence of events* happened to this identity? (correlation)
- *How many distinct commands* did one identity run in 10 minutes? (threshold)
- *What account was targeted*, and has it been dormant? (context enrichment)
- *Did the logging stop?* (any occurrence = alert, zero tolerance)

---

## Intelligence Sources

- Scattered Spider / UNC3944 CISA advisory (2023)
- Lapsus$ UK NCSC / CISA joint report (2022)
- Microsoft DART IR case studies — identity-focused intrusions (2023–2024)
- MITRE ATT&CK Cloud Matrix — IaaS and SaaS techniques
