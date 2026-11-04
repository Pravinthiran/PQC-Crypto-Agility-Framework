# stress_test_tier3.py
import os
import sys
import time
import json
import psutil
import pandas as pd
import numpy as np

# Ingest prioritization math from existing pipeline
from pqc_risk_prioritization import apply_mosca_and_mps

SCALES = [100, 500, 1000, 5000]
SYNTHETIC_DIR = "stress_test_data"
os.makedirs(SYNTHETIC_DIR, exist_ok=True)

ALGORITHMS = ["RSA", "ECC", "ECDSA", "ECDHE", "SHA1", "MD5", "AES-256", "SHA-256"]
KEY_SIZES = {
    "RSA": ["1024", "2048", "3072", "4096"],
    "ECC": ["SECP256R1", "SECP384R1", "SECP521R1"],
    "ECDSA": ["SECP256R1", "SECP384R1"],
    "ECDHE": ["X25519", "SECP256R1"],
    "SHA1": ["N/A"],
    "MD5": ["N/A"],
    "AES-256": ["256 bits"],
    "SHA-256": ["N/A"]
}
ASSET_TYPES = [
    "Source Code Function Call",
    "X.509 Keystore Certificate",
    "Network Transit Protocol",
    "X.509 Wire Certificate"
]

def generate_synthetic_cbom(n_assets: int) -> str:
    """Generates synthetic enterprise CBOM JSON inventories scaled to N records."""
    np.random.seed(42)  # Deterministic seed for reproducible academic results
    filepath = os.path.join(SYNTHETIC_DIR, f"cbom_scale_{n_assets}.json")
    
    records = []
    for i in range(1, n_assets + 1):
        alg = np.random.choice(ALGORITHMS, p=[0.30, 0.20, 0.15, 0.10, 0.10, 0.05, 0.05, 0.05])
        size = np.random.choice(KEY_SIZES[alg])
        asset_type = np.random.choice(ASSET_TYPES)
        
        record = {
            "bom_ref": f"synth-asset-{i:05d}",
            "component_name": f"Enterprise-{alg}-Service-{i}",
            "asset_type": asset_type,
            "primitive_family": "Asymmetric Cryptography" if alg in ["RSA", "ECC", "ECDSA", "ECDHE"] else "Symmetric/Digest",
            "algorithm": alg,
            "key_size_or_curve": size,
            "location": f"repo/service_{i % 50}/security.py:line_{i % 300}",
            "discovery_mode": "Synthetic Multi-Modal Ingestion"
        }
        records.append(record)
        
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2)
        
    return filepath

def execute_tier3_scale_evaluation():
    print("=" * 78)
    print("   TIER 3 EMPIRICAL PROOF: SCALABILITY & STRESS-TEST BENCHMARK ENGINE")
    print("=" * 78)
    
    benchmark_results = []
    process = psutil.Process()

    for scale in SCALES:
        print(f"\n[*] Evaluating Scale: N = {scale:,} cryptographic assets...")
        
        # 1. Synthesize target dataset
        json_file = generate_synthetic_cbom(scale)
        file_size_kb = round(os.path.getsize(json_file) / 1024, 2)
        
        # 2. Benchmark CBOM Deserialization and Ingestion Latency
        mem_before = process.memory_info().rss
        t0 = time.perf_counter()
        with open(json_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        df_raw = pd.DataFrame(data)
        t_ingest_ms = round((time.perf_counter() - t0) * 1000.0, 3)
        
        # 3. Benchmark Risk Prioritization & Mosca Computation Latency
        t1 = time.perf_counter()
        df_prioritized = apply_mosca_and_mps(df_raw)
        t_prioritize_ms = round((time.perf_counter() - t1) * 1000.0, 3)
        
        mem_after = process.memory_info().rss
        ram_delta_kb = max(0, round((mem_after - mem_before) / 1024, 2))
        
        total_time_ms = round(t_ingest_ms + t_prioritize_ms, 3)
        throughput_assets_sec = round((scale / (total_time_ms / 1000.0)), 1)
        mosca_violations = int(df_prioritized["mosca_violation"].sum())

        benchmark_results.append({
            "asset_scale_n": scale,
            "file_size_kb": file_size_kb,
            "cbom_ingestion_ms": t_ingest_ms,
            "prioritization_engine_ms": t_prioritize_ms,
            "total_latency_ms": total_time_ms,
            "throughput_assets_sec": throughput_assets_sec,
            "ram_delta_kb": ram_delta_kb,
            "mosca_violations_detected": mosca_violations
        })

    df_stress = pd.DataFrame(benchmark_results)

    print("\n" + "=" * 78)
    print("[+] EMPIRICAL TIER 3 BENCHMARK DATASET:")
    print("=" * 78)
    print(df_stress.to_string(index=False))

    # Export benchmark records
    csv_out = "tier3_scalability_metrics.csv"
    json_out = "tier3_scalability_metrics.json"
    df_stress.to_csv(csv_out, index=False)
    df_stress.to_json(json_out, orient="records", indent=2)

    print("\n[+] Verification & Export Summary:")
    print(f"    - CSV Output  : {os.path.abspath(csv_out)}")
    print(f"    - JSON Output : {os.path.abspath(json_out)}")
    print(f"    - Scale Tests : 100 -> 5,000 Assets Evaluated Successfully.")
    print("=" * 78)

if __name__ == "__main__":
    execute_tier3_scale_evaluation()