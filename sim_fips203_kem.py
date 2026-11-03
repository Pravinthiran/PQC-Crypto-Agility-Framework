# sim_fips203_kem.py
import os
import sys

# 1. Register liboqs MSVC binary directory for Windows
dll_dir = os.path.abspath(os.path.join(os.getcwd(), "liboqs", "install", "bin"))
if os.path.exists(dll_dir):
    os.environ["OQS_DIR"] = os.path.abspath(os.path.join(os.getcwd(), "liboqs", "install"))
    if hasattr(os, "add_dll_directory"):
        os.add_dll_directory(dll_dir)

import oqs


def run_fips203_simulation(mechanism: str = "ML-KEM-768"):
    """Job 1: Generates FIPS 203 keypairs, encapsulates, and decapsulates shared secrets."""
    print("=" * 65)
    print(f"   FIPS 203 (ML-KEM) STANDALONE SIMULATION: {mechanism}")
    print("=" * 65)

    enabled_kems = oqs.get_enabled_kem_mechanisms()
    if mechanism not in enabled_kems:
        raise ValueError(f"Algorithm '{mechanism}' is not enabled in the current liboqs build.")

    # 1. Receiver / Client Keypair Generation
    print(f"[*] Initializing Receiver KEM instance ({mechanism})...")
    with oqs.KeyEncapsulation(mechanism) as receiver:
        public_key = receiver.generate_keypair()
        print(f"[+] Keypair generated successfully.")
        print(f"    - Public Key Length : {len(public_key)} bytes")
        print(f"    - Claimed Details   : {receiver.details}")

        # 2. Sender / Peer Encapsulation
        print("\n[*] Sender encapsulating shared secret using Receiver's Public Key...")
        with oqs.KeyEncapsulation(mechanism) as sender:
            ciphertext, sender_shared_secret = sender.encap_secret(public_key)
            print(f"[+] Encapsulation successful.")
            print(f"    - Ciphertext Length : {len(ciphertext)} bytes")
            print(f"    - Secret Length     : {len(sender_shared_secret)} bytes")

        # 3. Receiver Decapsulation
        print("\n[*] Receiver decapsulating shared secret from ciphertext...")
        receiver_shared_secret = receiver.decap_secret(ciphertext)
        print(f"[+] Decapsulation complete.")

        # 4. Cryptographic Validation
        assert sender_shared_secret == receiver_shared_secret, "Decapsulation secret mismatch!"
        print(f"\n[+] VALIDATION: Shared secret match confirmed (FIPS 203 PASSED)!")
        print(f"    - Shared Secret (hex prefix): {sender_shared_secret[:16].hex()}...")

    print("=" * 65 + "\n")
    return {
        "status": "SUCCESS",
        "standard": "FIPS 203",
        "algorithm": mechanism,
        "public_key_bytes": len(public_key),
        "ciphertext_bytes": len(ciphertext),
        "shared_secret_bytes": len(sender_shared_secret),
    }


if __name__ == "__main__":
    run_fips203_simulation()