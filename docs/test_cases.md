# Test Cases

| Test No. | Test Scenario | Expected Result |
|---:|---|---|
| 1 | Run with bundled sample files | Assessment completes successfully |
| 2 | Missing `cve_id` column | Validation error is shown |
| 3 | Invalid CVE format | Warning is shown |
| 4 | Internet-facing asset with risky ports | Network exposure score increases |
| 5 | Asset with IDS exploit alert | IDS correlation score increases |
| 6 | PII + high data sensitivity | Privacy impact increases |
| 7 | KEV + internet + IDS alert | Priority becomes Critical or High |
| 8 | Old first detected date | SLA breach or due-soon status appears |
| 9 | Risk exception CSV provided | Exception fields are merged |
| 10 | What-if simulation | Before/after risk reduction appears |
| 11 | Detailed report export | CSV downloads successfully |
| 12 | Ticket export | Jira/ServiceNow-style CSV downloads |
| 13 | SHA-256 hash generation | Hash appears for each report |
| 14 | Hash verification with correct file | Verified status appears |
| 15 | Hash verification with modified file | Tampered/mismatch warning appears |
