import os
import sys

# 1. Register DLL directory for Windows
dll_dir = os.path.abspath(os.path.join(os.getcwd(), "liboqs", "install", "bin"))
if os.path.exists(dll_dir):
    os.environ["OQS_DIR"] = os.path.abspath(os.path.join(os.getcwd(), "liboqs", "install"))
    if hasattr(os, "add_dll_directory"):
        os.add_dll_directory(dll_dir)
    print(f"[+] Added DLL search directory: {dll_dir}")
else:
    print(f"[-] Warning: DLL directory not found at {dll_dir}")

import oqs

print(f"[+] liboqs version: {oqs.oqs_version()}")

# 2. Test FIPS 203 (ML-KEM-768)
target_kem = "ML-KEM-768"
enabled_kems = oqs.get_enabled_kem_mechanisms()
if target_kem in enabled_kems:
    print(f"[+] {target_kem} (FIPS 203): enabled")
    with oqs.KeyEncapsulation(target_kem) as client:
        public_key = client.generate_keypair()
        with oqs.KeyEncapsulation(target_kem) as server:
            ciphertext, shared_secret_server = server.encap_secret(public_key)
            shared_secret_client = client.decap_secret(ciphertext)
            assert shared_secret_client == shared_secret_server
            print(f"[+] {target_kem} encapsulation/decapsulation verified!")
else:
    print(f"[-] {target_kem} not found")

# 3. Test FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA)
target_sigs = ["ML-DSA-65", "SLH_DSA_PURE_SHAKE_128S"]
enabled_sigs = oqs.get_enabled_sig_mechanisms()

for sig in target_sigs:
    status = "enabled" if sig in enabled_sigs else "not found"
    print(f"[+] {sig}: {status}")

# Sign and verify test with SLH-DSA
target_slh = "SLH_DSA_PURE_SHAKE_128S"
if target_slh in enabled_sigs:
    with oqs.Signature(target_slh) as signer:
        signer_pub = signer.generate_keypair()
        msg = b"Transaction payload: transfer 50000 MYR"
        sig_data = signer.sign(msg)
        with oqs.Signature(target_slh) as verifier:
            is_valid = verifier.verify(msg, sig_data, signer_pub)
            print(f"[+] {target_slh} (FIPS 205) signature verification: {is_valid}")