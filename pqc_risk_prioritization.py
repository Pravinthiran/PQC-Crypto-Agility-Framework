# pqc_risk_prioritization.py
import json
import os
import pandas as pd


# =====================================================================
# JOB 1: Load CycloneDX 1.6 cbom.json into a pandas DataFrame
# =====================================================================
def load_cbom(cbom_path: str = "cbom.json") -> pd.DataFrame:
    """Ingests CycloneDX 1.6 cbom.json and flattens properties into tabular rows."""
    if not os.path.exists(cbom_path):
        raise FileNotFoundError(f"CBOM file not found at: {cbom_path}")

    with open(cbom_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    rows = []
    components = data.get("components", [])

    for component in components:
        # Extract name-value property pairs
        props = {p["name"]: p["value"] for p in component.get("properties", [])}

        row = {
            "bom_ref": component.get("bom-ref"),
            "component_name": component.get("name"),
            "asset_type": props.get("asset_type", "Unknown"),
            "location": props.get("location", "Unknown"),
            "primitive_family": props.get("primitive_family", "Unknown"),
            "algorithm": props.get("algorithm", "Unknown").upper(),
            "key_size_or_curve": props.get("key_size_or_curve", "Unknown"),
            "quantum_safe": props.get("quantum_safe", "false").lower() == "true",
            "vulnerability_type": props.get("vulnerability_type", "Unknown"),
            "migration_urgency": props.get("migration_urgency", "Medium"),
        }
        rows.append(row)

    return pd.DataFrame(rows)


# =====================================================================
# JOB 2: Static Metric Dictionaries & Mosca Timeline Parameters
# =====================================================================
VULNERABILITY_WEIGHTS = {
    "RSA": 10.0,      # Shor's Algorithm (Integer Factorization)
    "ECC": 10.0,      # Shor's Algorithm (ECDLP)
    "DSA": 10.0,      # Shor's Algorithm (DLP)
    "MD5": 4.0,       # Classical Collision Deprecation
    "SHA1": 5.0,      # Classical Collision Deprecation
    "AES-128": 3.0,   # Grover's effective 64-bit reduction
    "AES-256": 0.0,   # Quantum resistant symmetric cipher
}

CRITICALITY_WEIGHTS = {
    "Critical": 10.0,
    "High": 7.0,
    "Medium": 4.0,
    "Low": 2.0,
}

# Shelf life / Secrecy lifespan (D in years)
SHELF_LIFE_D = {
    "Public Key Infrastructure (PKI)": 10.0,
    "Asymmetric Cryptography": 7.0,
    "Hash Function": 3.0,
    "Unknown": 5.0,
}

# Migration & Deployment Lead Time (T in years)
MIGRATION_TIME_T = {
    "Public Key Infrastructure (PKI)": 3.0,
    "Asymmetric Cryptography": 2.0,
    "Hash Function": 1.0,
    "Unknown": 2.0,
}

# Estimated years to Cryptographically Relevant Quantum Computer (Q in years)
QUANTUM_THREAT_HORIZON_Q = 7.0


# =====================================================================
# JOB 3: Mosca's Theorem Logic Evaluation (D + T >= Q)
# =====================================================================
def apply_mosca_theorem(df: pd.DataFrame) -> pd.DataFrame:
    """Evaluates the condition D + T >= Q to identify Harvest Now, Decrypt Later risk."""
    # Assign vulnerability and business criticality scores
    df["vuln_weight"] = df["algorithm"].map(lambda alg: VULNERABILITY_WEIGHTS.get(alg, 5.0))
    df["crit_weight"] = df["migration_urgency"].map(lambda urg: CRITICALITY_WEIGHTS.get(urg, 4.0))

    # Map Mosca lifecycle durations (in years)
    df["D_shelf_life"] = df["primitive_family"].map(lambda fam: SHELF_LIFE_D.get(fam, 5.0))
    df["T_migration_time"] = df["primitive_family"].map(lambda fam: MIGRATION_TIME_T.get(fam, 2.0))
    df["Q_threat_horizon"] = QUANTUM_THREAT_HORIZON_Q

    # Mosca Inequality: D + T >= Q
    df["mosca_sum"] = df["D_shelf_life"] + df["T_migration_time"]
    df["mosca_violation"] = df["mosca_sum"] >= df["Q_threat_horizon"]
    df["hndl_gap_years"] = df["mosca_sum"] - df["Q_threat_horizon"]

    return df


# =====================================================================
# JOB 4: Compute Migration Priority Score (MPS) and Export
# =====================================================================
def calculate_mps_and_export(
    df: pd.DataFrame,
    csv_output: str = "prioritized_cbom.csv",
    json_output: str = "prioritized_cbom.json"
) -> pd.DataFrame:
    """Computes the Migration Priority Score (0-100 scale) and exports the ranked inventory."""
    # Formula: 45% Vulnerability + 35% Criticality + 20% Mosca Violation Surcharge
    df["MPS"] = (
        (df["vuln_weight"] * 4.5) +
        (df["crit_weight"] * 3.5) +
        (df["mosca_violation"].astype(int) * 20.0)
    ).round(2)

    # Sort descending by priority score
    df_sorted = df.sort_values(by="MPS", ascending=False).reset_index(drop=True)

    # Export prioritized results
    df_sorted.to_csv(csv_output, index=False)
    df_sorted.to_json(json_output, orient="records", indent=2)

    return df_sorted


# =====================================================================
# PIPELINE EXECUTION
# =====================================================================
def run_prioritization_pipeline():
    print("=" * 70)
    print("      PQC MIGRATION RISK & PRIORITIZATION PIPELINE (PHASE 3)")
    print("=" * 70)

    # Job 1
    cbom_path = os.path.join(os.getcwd(), "cbom.json")
    print(f"[*] Job 1: Ingesting cbom.json from {cbom_path}...")
    df_raw = load_cbom(cbom_path)
    print(f"[+] Successfully loaded {len(df_raw)} cryptographic assets into DataFrame.")

    # Job 2 & Job 3
    print("\n[*] Job 2 & 3: Applying metric dictionaries and Mosca's Theorem (D + T >= Q)...")
    df_evaluated = apply_mosca_theorem(df_raw)

    # Job 4
    print("\n[*] Job 4: Computing Migration Priority Scores (MPS) and exporting...")
    df_prioritized = calculate_mps_and_export(df_evaluated)

    # Display Results Table
    display_columns = [
        "algorithm",
        "key_size_or_curve",
        "migration_urgency",
        "D_shelf_life",
        "T_migration_time",
        "mosca_sum",
        "Q_threat_horizon",
        "mosca_violation",
        "MPS"
    ]
    print("\n[+] PRIORITIZED CRYPTOGRAPHIC ASSETS (Ranked by MPS):")
    print(df_prioritized[display_columns].to_string(index=True))

    print("\n" + "=" * 70)
    print(f"[+] Pipeline Execution Successful:")
    print(f"    - CSV Export  : {os.path.abspath('prioritized_cbom.csv')}")
    print(f"    - JSON Export : {os.path.abspath('prioritized_cbom.json')}")
    print(f"    - Total Assets Violating Mosca (D + T >= Q): {df_prioritized['mosca_violation'].sum()} / {len(df_prioritized)}")
    print("=" * 70)


if __name__ == "__main__":
    run_prioritization_pipeline()