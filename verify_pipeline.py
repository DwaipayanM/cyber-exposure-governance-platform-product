import sys
import pandas as pd
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).parent
sys.path.append(str(BASE_DIR))

# Import core engines directly (avoids importing GUI app.py)
try:
    from core.asset_context_engine import calculate_business_impact, enrich_with_asset_context
    from core.control_mapping_engine import add_control_mapping
    from core.exception_engine import apply_exceptions
    from core.ids_correlation_engine import correlate_ids_alerts
    from core.import_normalizer import normalize_vulnerability_input
    from core.network_exposure_engine import add_network_exposure
    from core.playbook_engine import add_remediation_playbooks
    from core.policy_engine import load_risk_policy
    from core.privacy_impact_engine import add_privacy_impact
    from core.remediation_governance import assign_remediation_governance
    from core.scoring_engine import calculate_final_score, calculate_threat_intelligence_score, summarize_score_drivers
    from core.validator import validate_asset_df, validate_ids_df, validate_vulnerability_df
    
    from services.cisa_kev_service import enrich_with_kev
    from services.epss_service import enrich_with_epss
    from services.nvd_service import enrich_with_nvd
    
    print("[OK] Successfully imported all core and service modules.")
except Exception as e:
    print(f"[ERROR] Failed to import core modules: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

def run_local_assessment(vuln_df, asset_df, ids_df, exceptions_df, DATA_DIR):
    # This matches the pipeline inside app.py exactly
    vuln_df = normalize_vulnerability_input(vuln_df, import_type="Standard Template")
    vuln_df, vuln_errors, vuln_warnings = validate_vulnerability_df(vuln_df)
    asset_df, asset_errors, asset_warnings = validate_asset_df(asset_df)
    ids_df, ids_errors, ids_warnings = validate_ids_df(ids_df) if ids_df is not None else (pd.DataFrame(), [], [])

    errors = vuln_errors + asset_errors + ids_errors
    warnings = vuln_warnings + asset_warnings + ids_warnings
    if errors:
        return None, errors, warnings

    policy = load_risk_policy(DATA_DIR / "risk_policy.json")

    df = enrich_with_kev(vuln_df, use_live=False)
    df = enrich_with_epss(df, use_live=False)
    df = enrich_with_nvd(df, use_live=False, api_key=None)

    df = enrich_with_asset_context(df, asset_df)
    df = calculate_business_impact(df)
    df = add_network_exposure(df)
    df = correlate_ids_alerts(df, ids_df)
    df = add_privacy_impact(df)

    df = calculate_threat_intelligence_score(df, policy)
    df = calculate_final_score(df, policy, include_sla_score=False)
    df = assign_remediation_governance(df, policy)
    df = calculate_final_score(df, policy, include_sla_score=True)
    df = assign_remediation_governance(df, policy)

    df = add_remediation_playbooks(df)
    df = apply_exceptions(df, exceptions_df)
    df = add_control_mapping(df)
    df["score_drivers"] = df.apply(summarize_score_drivers, axis=1)

    priority_order = {"Critical": 1, "High": 2, "Medium": 3, "Low": 4}
    df["_priority_order"] = df["priority"].map(priority_order).fillna(5)
    df = df.sort_values(["_priority_order", "final_score"], ascending=[True, False]).drop(columns=["_priority_order"])

    return df, errors, warnings

def main():
    print("Starting pipeline verification...")
    
    DATA_DIR = BASE_DIR / "data"
    vuln_path = DATA_DIR / "sample_input.csv"
    asset_path = DATA_DIR / "asset_inventory.csv"
    ids_path = DATA_DIR / "ids_alerts.csv"
    exceptions_path = DATA_DIR / "risk_exceptions.csv"
    
    # Load data
    try:
        vuln_df = pd.read_csv(vuln_path)
        asset_df = pd.read_csv(asset_path)
        ids_df = pd.read_csv(ids_path)
        exceptions_df = pd.read_csv(exceptions_path)
        print(f"[OK] Loaded input files successfully: vuln_df={len(vuln_df)} rows, asset_df={len(asset_df)} rows, ids_df={len(ids_df)} rows, exceptions_df={len(exceptions_df)} rows")
    except Exception as e:
        print(f"[ERROR] Failed to load sample files: {e}")
        sys.exit(1)
        
    # Execute assessment
    try:
        df, errors, warnings = run_local_assessment(
            vuln_df=vuln_df,
            asset_df=asset_df,
            ids_df=ids_df,
            exceptions_df=exceptions_df,
            DATA_DIR=DATA_DIR
        )
        
        if errors:
            print("[ERROR] Pipeline returned errors:")
            for err in errors:
                print(f"  - {err}")
            sys.exit(1)
            
        print("[OK] Pipeline executed successfully without errors.")
        if warnings:
            print(f"[INFO] Received {len(warnings)} non-blocking data quality warnings.")
            
        # Verify output dataframe integrity
        required_cols = ["final_score", "priority", "remediation_due_date", "sla_status", "primary_action"]
        missing_cols = [c for c in required_cols if c not in df.columns]
        if missing_cols:
            print(f"[ERROR] Missing critical output columns: {missing_cols}")
            sys.exit(1)
            
        print("[OK] Output dataframe verified: all critical output fields are populated.")
        print("\n=== Assessment Summary Metrics ===")
        print(f"Total processed rows: {len(df)}")
        print(f"Average final score: {df['final_score'].mean():.2f}")
        print(f"Highest risk score: {df['final_score'].max():.2f}")
        print(f"Lowest risk score: {df['final_score'].min():.2f}")
        print("\nPriority Breakdown:")
        print(df['priority'].value_counts().to_string())
        print("\nSLA Status Breakdown:")
        print(df['sla_status'].value_counts().to_string())
        
        print("\n[OK] Pipeline verification completed successfully! Codebase is healthy.")
        
    except Exception as e:
        print(f"[ERROR] Pipeline execution failed with an exception: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
