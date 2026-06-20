# CEGP — Mock Data Sets

Three complete, independent mock organisations, each with **all four input files** the
platform uses. Use any one set in place of the bundled sample data.

| Folder | Organisation | Sector | Files |
|---|---|---|---|
| `northwind_retail/`  | Northwind Retail Group   | Retail / e-commerce (PCI-DSS) | 4 |
| `vanguard_health/`   | Vanguard Health Systems  | Healthcare (HIPAA / PHI)      | 4 |
| `atlas_financial/`   | Atlas Financial Services | Banking (SOX / PCI-DSS)       | 4 |

Each folder contains the four files the app expects:

| File | Upload slot in the app |
|---|---|
| `vulnerabilities.csv`  | **Vulnerability file** |
| `asset_inventory.csv`  | **Asset inventory** |
| `ids_alerts.csv`       | **IDS/IPS alerts** |
| `risk_exceptions.csv`  | **Risk exceptions** |

## How to load a set

1. In the sidebar, turn **off** *Use bundled sample files*.
2. Upload the four files **from a single company folder** into their matching slots.
3. Enter an operator name and click **Run Cyber Exposure Assessment**.

## Notes

- The mock CVEs are drawn from the same CVE set covered by the platform's **offline
  threat-intelligence**, so each set enriches and scores correctly **without internet
  access** (keep live feeds off).
- Each set is internally consistent: every asset in the vulnerability file has a matching
  row in the asset inventory; IDS alerts and exceptions reference real assets/CVEs from
  that company.
- Each set is engineered to produce a realistic spread of priorities, SLA states (within /
  due-soon / breached), KEV hits, IDS-correlated assets, and a mix of valid and one expired
  risk exception — so every view in the dashboard is exercised.
- `business_criticality` uses **High / Medium / Low** (the app treats "Critical" here as a
  data-quality warning by design, so it is not used).
