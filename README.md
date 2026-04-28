# AWS Prowler Audit Tool 

A security auditing tool that combines Prowler scans with custom AWS security controls to generate client-ready audit reports.

---

## Features

- Runs Prowler scans across AWS environments
- Implements custom security checks:
  - Root MFA enforcement
  - IAM credential hygiene
  - Access key rotation
  - CloudTrail configuration
  - Encryption checks (S3, EBS, SNS, Logs)
- Generates:
  - Full raw report
  - Structured audit report (client-ready Excel)

---

## Architecture

1. Run Prowler scan
2. Parse ASFF JSON output
3. Apply:
   - Custom controls
   - Predefined security mappings
4. Generate audit reports

---

## Tech Stack

- Python
- AWS (boto3)
- Prowler
- Pandas (data processing)
- XlsxWriter (reporting)

---

