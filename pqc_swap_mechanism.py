# pqc_swap_mechanism.py
import json
import os
import sys

# Ensure liboqs Windows DLL paths
dll_dir = os.path.abspath(os.path.join(os.getcwd(), "liboqs", "install", "bin"))
if os.path.exists(dll_dir):
    os.environ["OQS_DIR"] = os.path.abspath(os.path.join(os.getcwd(), "liboqs", "install"))
    if hasattr(os, "add_dll_directory"):
        os.add_dll_directory(dll_dir)

from sim_fips203_kem import run_fips203_simulation
from sim_pqc_signatures import run_fips204_simulation, run_fips205_simulation


class CryptoSwapRouter:
    """Job 3: Resolves vulnerable assets from Phase 3 Risk Assessment

    and dispatches execution to the corresponding PQC primitive simulation.
    """

    def __init__(self, prioritized_cbom_path: str = "prioritized_cbom.json"):
        self.cbom_path = prioritized_cbom_path
        self.inventory = self._load_inventory()

    def _load_inventory(self):
        if not os.path.exists(self.cbom_path):
            raise FileNotFoundError(f"Prioritized CBOM not found at: {self.cbom_path}")
        with open(self.cbom_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return {item["bom_ref"]: item for item in data}

    def dispatch_swap(self, bom_ref: str, fallback_to_hash_sig: bool = False):
        """Routes a single asset by bom_ref to its target PQC remediation engine."""
        print("=" * 68)
        print(f"   PQC AGILITY SWAP MECHANISM: DISPATCHING {bom_ref}")
        print("=" * 68)

        if bom_ref not in self.inventory:
            print(f"[-] Asset '{bom_ref}' not found in prioritized inventory.")
            return None

        asset = self.inventory[bom_ref]
        alg = asset.get("algorithm", "").upper()
        prim_family = asset.get("primitive_family", "")
        asset_type = asset.get("asset_type", "")
        mps_score = asset.get("MPS", 0.0)

        print(f"[*] Target Asset        : {asset.get('component_name')}")
        print(f"    - Location          : {asset.get('location')}")
        print(f"    - Current Primitive : {alg} ({asset.get('key_size_or_curve')})")
        print(f"    - Migration Urgency : {asset.get('migration_urgency')} (MPS: {mps_score})")

        # Routing Decision Tree
        if "KEY GENERATION" in asset_type.upper() or prim_family == "Asymmetric Cryptography":
            print("[+] Routing Decision: Asymmetric Key Exchange / Encryption flagged.")
            print("[+] Remediating with FIPS 203 (ML-KEM-768)...")
            result = run_fips203_simulation("ML-KEM-768")

        elif "CERTIFICATE" in asset_type.upper() or prim_family == "Public Key Infrastructure (PKI)":
            if fallback_to_hash_sig:
                print("[+] Routing Decision: PKI Certificate -> Stateless Hash Signature Fallback.")
                print("[+] Remediating with FIPS 205 (SLH-DSA)...")
                result = run_fips205_simulation(
                    "SLH_DSA_PURE_SHAKE_128S",
                    test_payload=f"Cert Verification: {asset.get('location')}".encode()
                )
            else:
                print("[+] Routing Decision: PKI Certificate -> Primary Lattice Signature.")
                print("[+] Remediating with FIPS 204 (ML-DSA-65)...")
                result = run_fips204_simulation(
                    "ML-DSA-65",
                    test_payload=f"Cert Verification: {asset.get('location')}".encode()
                )

        elif "HASH" in prim_family.upper() or alg in ["MD5", "SHA1"]:
            print(f"[!] Classical hash function detected ({alg}).")
            print("[+] Recommendation: Digest upgrade to SHA-256 / SHA3-256 (Non-asymmetric PQC action).")
            result = {"standard": "FIPS 180-4", "algorithm": "SHA-256", "status": "REPLACED"}

        else:
            print("[-] Unknown cryptographic primitive. Cannot dispatch swap.")
            result = {"status": "UNKNOWN"}

        return result

    def route_all_high_priority(self, mps_threshold: float = 80.0):
        """Batch-routes all high-risk assets exceeding the MPS threshold."""
        print("\n" + "#" * 68)
        print(f"   EXECUTING BATCH SWAP FOR ALL ASSETS (MPS >= {mps_threshold})")
        print("#" * 68 + "\n")

        high_priority = [
            ref for ref, item in self.inventory.items()
            if item.get("MPS", 0.0) >= mps_threshold
        ]

        results = {}
        for ref in high_priority:
            results[ref] = self.dispatch_swap(ref)

        return results


if __name__ == "__main__":
    router = CryptoSwapRouter()

    # 1. Test Single Asset Routing (Targeting RSA keygen: crypto-asset-3)
    print("\n--- TEST 1: Single Target Dispatch (crypto-asset-3) ---")
    router.dispatch_swap("crypto-asset-3")

    # 2. Test Single Asset Routing (Targeting X.509 PKI Cert: crypto-asset-5)
    print("\n--- TEST 2: Single Target Dispatch (crypto-asset-5) ---")
    router.dispatch_swap("crypto-asset-5")