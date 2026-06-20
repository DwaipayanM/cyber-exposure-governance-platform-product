# Project Report Outline

## 1. Introduction
Explain cyber exposure management, vulnerability overload, and need for risk-based prioritization.

## 2. Problem Statement
Traditional vulnerability reports contain too many CVEs. Security teams need a business-aligned prioritization method.

## 3. Objectives
- Ingest vulnerability exposure data.
- Enrich CVEs using public threat intelligence.
- Correlate asset, network, IDS/IPS, and privacy context.
- Calculate final cyber exposure score.
- Assign SLA and remediation ownership.
- Generate remediation playbooks and reports.
- Verify report integrity using SHA-256.

## 4. Scope
Included: CSV ingestion, threat enrichment, scoring, dashboards, governance, simulation, audit reporting.
Excluded: live network scanning, agent installation, full SIEM integration, full RBAC.

## 5. System Architecture
Import → Normalize → Enrich → Correlate → Prioritize → Govern → Simulate → Report → Audit.

## 6. Data Sources
- CISA KEV
- FIRST EPSS
- NVD CVE API
- Asset inventory
- IDS/IPS alerts
- Risk exceptions

## 7. Methodology
Explain scoring dimensions:
- Threat intelligence
- Business impact
- Network exposure
- IDS correlation
- Privacy impact
- SLA governance

## 8. Algorithm
Describe scoring weights from `risk_policy.json`.

## 9. Implementation
Explain Python, Streamlit, pandas, services, and core engines.

## 10. Testing
Reference `test_cases.md`.

## 11. Results
Include screenshots of executive dashboard, analyst queue, simulation, and report integrity.

## 12. Syllabus Mapping
Reference `syllabus_mapping.md`.

## 13. Limitations
- Does not perform live scanning.
- IDS/IPS data is CSV-based for demo.
- Some external feeds may be unavailable; fallback data is used.
- Risk scoring is explainable and configurable but not a certified quantitative risk model.

## 14. Future Enhancements
- Nessus/Qualys/OpenVAS API connectors.
- SIEM integration.
- ServiceNow/Jira API ticket creation.
- Database backend.
- SSO/RBAC.
- Docker/Kubernetes deployment.
- ML-assisted remediation prediction.

## 15. Conclusion
The project demonstrates a practical cyber exposure governance workflow that can help organizations prioritize remediation based on risk, not just severity.
