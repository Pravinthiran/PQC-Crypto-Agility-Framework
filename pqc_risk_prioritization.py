# pqc_risk_prioritization.py
import os
import sys
import json
import pandas as pd
import numpy as np

# =====================================================================
# CORE RISK PARAMETERS & THEORETICAL WEIGHTS (Mosca & MPS)
# =====================================================================
# Q: Estimated years until Cryptographically Relevant Quantum Computer (CRQC)
Q_THREAT_HORIZON_YEARS = 7.0

# Algorithm Vulnerability Scores (Scale: 0 - 10)
# 10 = Broken by Shor's (RSA, ECC, ECDSA, ECDH)
# 5  = Classical collisions/weaknesses (MD5, SHA-1)
# 0  = Quantum resistant symmetric baselines (AES-256, SHA-256/384/512)
VULNERABILITY_WEIGHTS = {
    "RSA": 10.0,
    "ECC": 10.0,
    "ECDSA": 10.0,
    "ECDHE": 10.0,
    "DSA": 10.0,
    "MD5": 5.0,
    "SHA1": 5.0,
    "SHA-1": 5.0,
    "AES": 0.0,
    "AES-256": 0.0,
    "SHA-256": 0.0,
    "UNKNOWN": 5.0
}

# Criticality Weights by System Function (Scale: 1 - 10)
CRITICALITY_TIERS = {
    "Mission-Critical": 10.0,
    "High": 8.0,
    "Medium": 5.0,
    "Low": 2.0
}


def load_cbom(filepath: str = "cbom.json") -> pd.DataFrame:
    """Job 1: Ingests cbom.json supporting both dictionary wrappers and raw lists."""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"CBOM file not found at: {filepath}")

    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, dict):
        components = data.get("components", data.get("assets", []))
        if not components and any(isinstance(v, dict) for v in data.values()):
            components = [v for v in data.values() if isinstance(v, dict)]
    elif isinstance(data, list):
        components = data
    else:
        components = []

    if not components:
        raise ValueError(f"No valid cryptographic components found inside {filepath}")

    records = []
    for item in components:
        if not isinstance(item, dict):
            continue
        record = {
            "bom_ref": item.get("bom_ref", f"crypto-asset-{len(records)+1}"),
            "component_name": item.get("component_name", item.get("name", "Cryptographic Primitive")),
            "asset_type": item.get("asset_type", item.get("type", "Cryptographic Asset")),
            "primitive_family": item.get("primitive_family", "Asymmetric Cryptography"),
            "algorithm": item.get("algorithm", "UNKNOWN"),
            "key_size_or_curve": item.get("key_size_or_curve", item.get("key_size", "N/A")),
            "location": item.get("location", "N/A"),
            "discovery_mode": item.get("discovery_mode", "Static/Keystore Analysis")
        }
        records.append(record)

    df = pd.DataFrame(records)
    print(f"[+] Successfully loaded {len(df)} cryptographic assets into DataFrame.")
    return df


def assign_vulnerability_weight(algorithm_str: str) -> float:
    """Matches algorithm names and cipher suites to vulnerability scores."""
    alg_upper = str(algorithm_str).upper()
    
    # Check for asymmetric primitives breakable by Shor's
    if any(k in alg_upper for k in ["RSA", "ECC", "ECDSA", "ECDHE", "SECP", "PRIME256"]):
        return 10.0
    elif any(k in alg_upper for k in ["MD5", "SHA1", "SHA-1"]):
        return 5.0
    elif any(k in alg_upper for k in ["AES-256", "SHA-256", "SHA-384", "SHA-512"]):
        return 0.0
    return 6.0


def assign_system_criticality(row: pd.Series) -> tuple[float, float, float]:
    """Derives Criticality Weight, Data Shelf-Life (D), and Migration Time (T).

    Financial transactions and wire transits carry high HNDL risk exposure.
    """
    asset_type = str(row.get("asset_type", "")).upper()
    comp_name = str(row.get("component_name", "")).upper()
    loc = str(row.get("location", "")).upper()

    # Financial ledger / wire transit / core certificates
    if "TRANSIT" in asset_type or "WIRE" in asset_type or "CERT" in asset_type or "BANK" in loc:
        crit_weight = 10.0
        d_shelf_life = 8.0     # Financial records retain confidentiality value for 8+ years
        t_migration = 3.0      # System-wide PKI/network infrastructure swap requires ~3 years
    elif "KEY GENERATION" in asset_type or "ASYMMETRIC" in str(row.get("primitive_family", "")).upper():
        crit_weight = 8.0
        d_shelf_life = 7.0     # Critical encryption keys
        t_migration = 2.0      # Application-level migration
    else:
        crit_weight = 4.0
        d_shelf_life = 3.0     # Routine hashes/caches
        t_migration = 1.0

    return crit_weight, d_shelf_life, t_migration


def apply_mosca_and_mps(df: pd.DataFrame) -> pd.DataFrame:
    """Job 2, 3 & 4: Calculates Mosca's Theorem (D + T >= Q) and Migration Priority Score (MPS)."""
    df = df.copy()

    # 1. Derive algorithm vulnerability weights
    df["vuln_weight"] = df["algorithm"].apply(assign_vulnerability_weight)

    # 2. Derive criticality, D (shelf-life), and T (migration time)
    crit_tuples = df.apply(assign_system_criticality, axis=1)
    df["crit_weight"] = [t[0] for t in crit_tuples]
    df["D_shelf_life"] = [t[1] for t in crit_tuples]
    df["T_migration_time"] = [t[2] for t in crit_tuples]

    # 3. Apply Mosca's Theorem: Mosca Sum = D + T
    df["mosca_sum"] = df["D_shelf_life"] + df["T_migration_time"]
    df["Q_threat_horizon"] = Q_THREAT_HORIZON_YEARS
    df["mosca_violation"] = df["mosca_sum"] >= df["Q_threat_horizon"]

    # 4. Compute Normalized Migration Priority Score (MPS)
    # Formula: MPS = (0.45 * Vuln + 0.35 * Crit) * 10 + (20 if Mosca violated else 0)
    base_score = (0.45 * df["vuln_weight"] + 0.35 * df["crit_weight"]) * 10.0
    mosca_bonus = np.where(df["mosca_violation"], 20.0, 0.0)
    df["MPS"] = np.clip(base_score + mosca_bonus, 0.0, 100.0).round(1)

    # 5. Assign Urgency Categories
    def get_urgency(score: float) -> str:
        if score >= 80.0:
            return "Critical"
        elif score >= 50.0:
            return "High"
        elif score >= 30.0:
            return "Medium"
        return "Low"

    df["migration_urgency"] = df["MPS"].apply(get_urgency)

    # Rank highest MPS first
    df = df.sort_values(by=["MPS", "mosca_sum"], ascending=[False, False]).reset_index(drop=True)
    return df


def run_prioritization_pipeline(cbom_path: str = "cbom.json"):
    print("=" * 70)
    print("      PQC MIGRATION RISK & PRIORITIZATION PIPELINE (PHASE 3)")
    print("=" * 70)

    print(f"[*] Job 1: Ingesting CBOM from {os.path.abspath(cbom_path)}...")
    df_raw = load_cbom(cbom_path)

    print("\n[*] Job 2 & 3: Applying metric dictionaries and Mosca's Theorem (D + T >= Q)...")
    df_prioritized = apply_mosca_and_mps(df_raw)

    print("\n[*] Job 4: Computing Migration Priority Scores (MPS) and exporting...")
    display_cols = [
        "bom_ref", "algorithm", "key_size_or_curve", "migration_urgency",
        "D_shelf_life", "T_migration_time", "mosca_sum", "Q_threat_horizon", "mosca_violation", "MPS"
    ]
    print("\n[+] PRIORITIZED CRYPTOGRAPHIC ASSETS (Ranked by MPS):")
    print(df_prioritized[display_cols].to_string(index=False))

    # Export deliverables for Phase 4 simulation and Phase 5 dashboard
    csv_out = "prioritized_cbom.csv"
    json_out = "prioritized_cbom.json"
    df_prioritized.to_csv(csv_out, index=False)
    df_prioritized.to_json(json_out, orient="records", indent=2)

    total_violators = df_prioritized["mosca_violation"].sum()
    print("\n" + "=" * 70)
    print("[+] Pipeline Execution Successful:")
    print(f"    - CSV Export  : {os.path.abspath(csv_out)}")
    print(f"    - JSON Export : {os.path.abspath(json_out)}")
    print(f"    - Total Assets Violating Mosca (D + T >= Q): {total_violators} / {len(df_prioritized)}")
    print("=" * 70)
    return df_prioritized


if __name__ == "__main__":
    run_prioritization_pipeline()