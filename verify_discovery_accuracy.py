# verify_discovery_accuracy.py
import json
import os
import pandas as pd

def run_discovery_verification():
    print("=" * 76)
    print("   DISCOVERY ACCURACY CONFUSION MATRIX & VERIFICATION ENGINE")
    print("=" * 76)

    # 1. Ground Truth Baseline of the planted testbed repository & network
    ground_truth = {
        # Positives (Assets that MUST be detected and classified into the CBOM)
        "crypto-asset-1": {"component": "RSA-2048-KeyGen-Module", "type": "AST Code", "is_vulnerable": True},
        "crypto-asset-2": {"component": "X509-Bank-Gateway-Certificate", "type": "Keystore Cert", "is_vulnerable": True},
        "crypto-asset-3": {"component": "ECC-ECDSA-Auth-Service", "type": "AST Code", "is_vulnerable": True},
        "crypto-asset-4": {"component": "Legacy-Integrity-Checksum-SHA1", "type": "AST Code", "is_vulnerable": True},
        "crypto-asset-5": {"component": "Legacy-Password-Hasher-MD5", "type": "AST Code", "is_vulnerable": True},
        "net-cert-8443":  {"component": "Network-Presented-Cert-RSA", "type": "Wire Cert", "is_vulnerable": True},
        "net-cipher-8443":{"component": "Network-Transit-Cipher", "type": "Wire Cipher", "is_vulnerable": True},
        
        # Planted Negatives in testbed (Clean helper code & safe hashes that MUST NOT be flagged as PQC migration targets)
        "neg-code-helper-1": {"component": "Base64-Encoder-Module", "type": "AST Code", "is_vulnerable": False},
        "neg-code-helper-2": {"component": "UUID-Generation-Token", "type": "AST Code", "is_vulnerable": False},
        "neg-cert-clean-3":  {"component": "Internal-Local-CA-Safe", "type": "Keystore Cert", "is_vulnerable": False}
    }

    # 2. Ingest the actual CBOM produced by your discovery modules
    cbom_path = "cbom.json"
    if not os.path.exists(cbom_path):
        print(f"[-] Missing {cbom_path}. Run discovery modules first.")
        return

    with open(cbom_path, "r", encoding="utf-8") as f:
        discovered_assets = json.load(f)

    discovered_refs = set(a.get("bom_ref") for a in discovered_assets)

    # 3. Calculate Confusion Matrix Elements
    TP = 0
    FP = 0
    FN = 0
    TN = 0

    evaluation_rows = []

    for ref, meta in ground_truth.items():
        detected = ref in discovered_refs
        is_pos = meta["is_vulnerable"]

        if is_pos and detected:
            classification = "True Positive (TP)"
            TP += 1
        elif not is_pos and not detected:
            classification = "True Negative (TN)"
            TN += 1
        elif not is_pos and detected:
            classification = "False Positive (FP)"
            FP += 1
        elif is_pos and not detected:
            classification = "False Negative (FN)"
            FN += 1

        evaluation_rows.append({
            "Asset Reference": ref,
            "Target Component": meta["component"],
            "Scanning Subsystem": meta["type"],
            "Expected Vulnerability": meta["is_vulnerable"],
            "Detected in CBOM": detected,
            "Classification": classification
        })

    total_eval = len(ground_truth)
    accuracy = (TP + TN) / total_eval
    precision = TP / (TP + FP) if (TP + FP) > 0 else 0.0
    recall = TP / (TP + FN) if (TP + FN) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    df_eval = pd.DataFrame(evaluation_rows)
    print("\n[+] ITEM-BY-ITEM GROUND TRUTH AUDIT:")
    print(df_eval[["Asset Reference", "Scanning Subsystem", "Detected in CBOM", "Classification"]].to_string(index=False))

    summary_metrics = pd.DataFrame([{
        "Total Ground Truth Items": total_eval,
        "True Positives (TP)": TP,
        "True Negatives (TN)": TN,
        "False Positives (FP)": FP,
        "False Negatives (FN)": FN,
        "Accuracy": f"{accuracy * 100:.2f}%",
        "Precision": f"{precision * 100:.2f}%",
        "Recall": f"{recall * 100:.2f}%",
        "F1-Score": f"{f1 * 100:.2f}%"
    }])

    print("\n" + "=" * 76)
    print("[+] FORMAL DISCOVERY ACCURACY METRICS:")
    print("=" * 76)
    print(summary_metrics.to_string(index=False))

    summary_metrics.to_csv("discovery_accuracy_metrics.csv", index=False)
    print("\n[+] Verification data saved to: discovery_accuracy_metrics.csv")
    print("=" * 76)

if __name__ == "__main__":
    run_discovery_verification()