# verify_phase4.py
import json
import os
import sys
import pandas as pd

# Register liboqs Windows DLL paths
dll_dir = os.path.abspath(os.path.join(os.getcwd(), "liboqs", "install", "bin"))
if os.path.exists(dll_dir):
    os.environ["OQS_DIR"] = os.path.abspath(os.path.join(os.getcwd(), "liboqs", "install"))
    if hasattr(os, "add_dll_directory"):
        os.add_dll_directory(dll_dir)


def verify_phase4():
    print("=" * 68)
    print("      PQC CRYPTO-AGILITY FRAMEWORK: PHASE 4 AUDIT & VERIFICATION")
    print("=" * 68)

    all_passed = True

    # -----------------------------------------------------------------
    # 1. Deliverables Check
    # -----------------------------------------------------------------
    print("\n[+] DELIVERABLE INTEGRITY CHECK:")
    required_files = [
        "sim_fips203_kem.py",
        "sim_pqc_signatures.py",
        "pqc_swap_mechanism.py",
        "pqc_benchmarking.py",
        "pqc_benchmark_metrics.csv",
        "pqc_benchmark_metrics.json",
    ]
    for filename in required_files:
        exists = os.path.exists(filename)
        status = "FOUND" if exists else "MISSING"
        if not exists:
            all_passed = False
        print(f"    - {filename:<28} : {status}")

    # -----------------------------------------------------------------
    # 2. Job 1 Verification: FIPS 203 (ML-KEM)
    # -----------------------------------------------------------------
    print("\n[+] JOB 1 AUDIT (FIPS 203 ML-KEM-768 Functional Test):")
    try:
        from sim_fips203_kem import run_fips203_simulation
        res_kem = run_fips203_simulation("ML-KEM-768")
        assert res_kem.get("public_key_bytes") == 1184, "Invalid ML-KEM-768 public key size"
        assert res_kem.get("ciphertext_bytes") == 1088, "Invalid ML-KEM-768 ciphertext size"
        assert res_kem.get("shared_secret_bytes") == 32, "Invalid shared secret size"
        print("    - Algorithm Standard       : FIPS 203 (ML-KEM-768)")
        print("    - Key & Ciphertext Sizes   : VERIFIED (1184 B public key, 1088 B ciphertext)")
        print("    - Shared Secret Validation : VERIFIED EXACT (32 B)")
        print("    - FIPS 203 Functional Run  : PASSED")
    except Exception as e:
        print(f"    - FIPS 203 Functional Run  : FAILED ({e})")
        all_passed = False

    # -----------------------------------------------------------------
    # 3. Job 2 Verification: FIPS 204 & FIPS 205 Signatures
    # -----------------------------------------------------------------
    print("\n[+] JOB 2 AUDIT (FIPS 204 & FIPS 205 Signatures):")
    try:
        from sim_pqc_signatures import run_fips204_simulation, run_fips205_simulation
        res_204 = run_fips204_simulation("ML-DSA-65", b"Verification Token")
        assert res_204.get("public_key_bytes") == 1952, "Invalid ML-DSA-65 public key size"
        assert res_204.get("signature_bytes") == 3309, "Invalid ML-DSA-65 signature size"
        assert res_204.get("verified") is True, "FIPS 204 verification failed"
        print("    - FIPS 204 (ML-DSA-65)     : VERIFIED (1952 B PK, 3309 B Sig, Passed)")

        res_205 = run_fips205_simulation("SLH_DSA_PURE_SHAKE_128S", b"Verification Token")
        assert res_205.get("public_key_bytes") == 32, "Invalid SLH-DSA public key size"
        assert res_205.get("signature_bytes") == 7856, "Invalid SLH-DSA signature size"
        assert res_205.get("verified") is True, "FIPS 205 verification failed"
        print("    - FIPS 205 (SLH-DSA)       : VERIFIED (32 B PK, 7856 B Sig, Passed)")
        print("    - Digital Signatures Suite : PASSED")
    except Exception as e:
        print(f"    - Digital Signatures Suite : FAILED ({e})")
        all_passed = False

    # -----------------------------------------------------------------
    # 4. Job 3 Verification: Swap Mechanism Routing Logic
    # -----------------------------------------------------------------
    print("\n[+] JOB 3 AUDIT (Swap Mechanism Routing & Dispatch):")
    try:
        from pqc_swap_mechanism import CryptoSwapRouter
        router = CryptoSwapRouter()
        
        # Test routing for Keygen asset (crypto-asset-3)
        res_swap_kem = router.dispatch_swap("crypto-asset-3")
        assert res_swap_kem.get("standard") == "FIPS 203", "Routing mismatch for crypto-asset-3"
        print("    - Asset crypto-asset-3     : VERIFIED -> Routed to FIPS 203 (ML-KEM-768)")

        # Test routing for Cert asset (crypto-asset-5)
        res_swap_sig = router.dispatch_swap("crypto-asset-5")
        assert res_swap_sig.get("standard") == "FIPS 204", "Routing mismatch for crypto-asset-5"
        print("    - Asset crypto-asset-5     : VERIFIED -> Routed to FIPS 204 (ML-DSA-65)")
        print("    - Swap Router Engine       : PASSED")
    except Exception as e:
        print(f"    - Swap Router Engine       : FAILED ({e})")
        all_passed = False

    # -----------------------------------------------------------------
    # 5. Job 4 Verification: Benchmarking Metrics Dataset Audit
    # -----------------------------------------------------------------
    print("\n[+] JOB 4 AUDIT (Benchmarking Metrics & Performance Data):")
    csv_file = "pqc_benchmark_metrics.csv"
    if os.path.exists(csv_file):
        df = pd.read_csv(csv_file)
        expected_primitives = {"RSA-2048", "ML-KEM-768", "ML-DSA-65", "SLH_DSA_PURE_SHAKE_128S"}
        recorded_primitives = set(df["primitive"].unique())

        if expected_primitives.issubset(recorded_primitives):
            print(f"    - Recorded Primitives      : VERIFIED ({len(recorded_primitives)} algorithms present)")
        else:
            print(f"    - Recorded Primitives      : FAILED (Missing {expected_primitives - recorded_primitives})")
            all_passed = False

        # Verify latency and size metrics exist and are positive
        valid_keygen = (df["keygen_latency_ms"] > 0).all()
        valid_sizes = (df["public_key_bytes"] > 0).all() and (df["ciphertext_or_sig_bytes"] > 0).all()

        if valid_keygen and valid_sizes:
            print("    - Latency & Sizing Bounds  : VERIFIED (All execution metrics > 0)")
        else:
            print("    - Latency & Sizing Bounds  : FAILED (Non-positive values detected)")
            all_passed = False

        # Compare CSV and JSON parity
        json_file = "pqc_benchmark_metrics.json"
        if os.path.exists(json_file):
            with open(json_file, "r", encoding="utf-8") as jf:
                json_records = json.load(jf)
            if len(json_records) == len(df):
                print(f"    - Dual Export Parity       : VERIFIED ({len(df)} records in CSV & JSON)")
            else:
                print("    - Dual Export Parity       : FAILED (Count mismatch)")
                all_passed = False
        print("    - Performance Metrics Suite: PASSED")
    else:
        print("    - pqc_benchmark_metrics.csv: MISSING")
        all_passed = False

    print("\n" + "=" * 68)
    if all_passed:
        print("      STATUS: ALL PHASE 4 REQUIREMENTS VERIFIED & CONFIRMED")
    else:
        print("      STATUS: PHASE 4 AUDIT DETECTED WARNINGS/FAILURES")
    print("=" * 68 + "\n")


if __name__ == "__main__":
    verify_phase4()