# sim_pqc_signatures.py
import os
import sys

# Register liboqs MSVC binary directory for Windows
dll_dir = os.path.abspath(os.path.join(os.getcwd(), "liboqs", "install", "bin"))
if os.path.exists(dll_dir):
    os.environ["OQS_DIR"] = os.path.abspath(os.path.join(os.getcwd(), "liboqs", "install"))
    if hasattr(os, "add_dll_directory"):
        os.add_dll_directory(dll_dir)

import oqs


def run_fips204_simulation(mechanism: str = "ML-DSA-65", test_payload: bytes = b"CRQC Migration Signature Verification"):
    """Job 2 (Part A): FIPS 204 ML-DSA digital signature simulation."""
    print("=" * 68)
    print(f"   FIPS 204 (ML-DSA) STANDALONE SIMULATION: {mechanism}")
    print("=" * 68)

    enabled_sigs = oqs.get_enabled_sig_mechanisms()
    if mechanism not in enabled_sigs:
        raise ValueError(f"Algorithm '{mechanism}' not enabled in liboqs.")

    # 1. Signer Keypair Generation
    print(f"[*] Initializing Signer ({mechanism})...")
    with oqs.Signature(mechanism) as signer:
        public_key = signer.generate_keypair()
        print(f"[+] Keypair generated.")
        print(f"    - Public Key Length : {len(public_key)} bytes")
        print(f"    - Details           : {signer.details}")

        # 2. Signing Payload
        print(f"\n[*] Signing payload: '{test_payload.decode()}'...")
        signature = signer.sign(test_payload)
        print(f"[+] Signature created.")
        print(f"    - Signature Length  : {len(signature)} bytes")

    # 3. Verifier Verification
    print("\n[*] Initializing Verifier...")
    with oqs.Signature(mechanism) as verifier:
        is_valid = verifier.verify(test_payload, signature, public_key)
        assert is_valid, "FIPS 204 signature verification failed!"
        print(f"[+] VALIDATION: Signature verification SUCCESS (FIPS 204 PASSED)!")

    print("=" * 68 + "\n")
    return {
        "standard": "FIPS 204",
        "algorithm": mechanism,
        "public_key_bytes": len(public_key),
        "signature_bytes": len(signature),
        "verified": is_valid
    }


def run_fips205_simulation(mechanism: str = "SLH_DSA_PURE_SHAKE_128S", test_payload: bytes = b"SLH-DSA Hash-Based Token"):
    """Job 2 (Part B): FIPS 205 SLH-DSA stateless hash signature simulation."""
    print("=" * 68)
    print(f"   FIPS 205 (SLH-DSA) STANDALONE SIMULATION: {mechanism}")
    print("=" * 68)

    enabled_sigs = oqs.get_enabled_sig_mechanisms()
    if mechanism not in enabled_sigs:
        raise ValueError(f"Algorithm '{mechanism}' not enabled in liboqs.")

    # 1. Signer Keypair Generation
    print(f"[*] Initializing Stateless Hash Signer ({mechanism})...")
    with oqs.Signature(mechanism) as signer:
        public_key = signer.generate_keypair()
        print(f"[+] Keypair generated.")
        print(f"    - Public Key Length : {len(public_key)} bytes")

        # 2. Signing Payload
        print(f"\n[*] Signing payload: '{test_payload.decode()}'...")
        signature = signer.sign(test_payload)
        print(f"[+] Signature created.")
        print(f"    - Signature Length  : {len(signature)} bytes")

    # 3. Verifier Verification
    print("\n[*] Initializing Verifier...")
    with oqs.Signature(mechanism) as verifier:
        is_valid = verifier.verify(test_payload, signature, public_key)
        assert is_valid, "FIPS 205 signature verification failed!"
        print(f"[+] VALIDATION: Stateless signature verification SUCCESS (FIPS 205 PASSED)!")

    print("=" * 68 + "\n")
    return {
        "standard": "FIPS 205",
        "algorithm": mechanism,
        "public_key_bytes": len(public_key),
        "signature_bytes": len(signature),
        "verified": is_valid
    }


if __name__ == "__main__":
    run_fips204_simulation()
    run_fips205_simulation()