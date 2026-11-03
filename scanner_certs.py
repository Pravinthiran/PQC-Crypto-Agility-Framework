# scanner_certs.py
import os
from typing import Any, Dict, List
from OpenSSL import crypto


def scan_certificates(cert_dir: str) -> List[Dict[str, Any]]:
    """Parses X.509 certificates using pyOpenSSL to extract cryptographic parameters."""
    findings = []

    if not os.path.exists(cert_dir):
        print(f"[-] Certificate directory not found: {cert_dir}")
        return findings

    for root, _, files in os.walk(cert_dir):
        for file in files:
            if file.endswith((".crt", ".cer", ".pem")):
                cert_path = os.path.join(root, file)
                try:
                    with open(cert_path, "rb") as f:
                        cert_data = f.read()

                    # Load X.509 Certificate
                    x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)
                    pub_key = x509.get_pubkey()

                    # Determine Public Key Algorithm
                    key_type_id = pub_key.type()
                    if key_type_id == crypto.TYPE_RSA:
                        key_type = "RSA"
                        key_bits = pub_key.bits()
                        quantum_safe = False
                        vuln = "Shor's Algorithm (Factorization Vulnerability)"
                        urgency = "Critical"
                    elif key_type_id == crypto.TYPE_DSA:
                        key_type = "DSA"
                        key_bits = pub_key.bits()
                        quantum_safe = False
                        vuln = "Shor's Algorithm (Discrete Logarithm Vulnerability)"
                        urgency = "Critical"
                    else:
                        key_type = "ECC / Other"
                        key_bits = pub_key.bits()
                        quantum_safe = False
                        vuln = "Shor's Algorithm (CRQC Vulnerability)"
                        urgency = "Critical"

                    # Signature Algorithm
                    sig_alg = x509.get_signature_algorithm().decode("utf-8")
                    subject_components = dict(x509.get_subject().get_components())
                    common_name = subject_components.get(b"CN", b"Unknown").decode("utf-8")

                    findings.append({
                        "asset_type": "X.509 Digital Certificate",
                        "location": cert_path,
                        "common_name": common_name,
                        "primitive_family": "Public Key Infrastructure (PKI)",
                        "algorithm": key_type,
                        "key_size_or_curve": f"{key_bits} bits",
                        "signature_algorithm": sig_alg,
                        "quantum_safe": quantum_safe,
                        "vulnerability_type": vuln,
                        "migration_urgency": urgency
                    })

                except Exception as err:
                    print(f"[-] Error parsing certificate {cert_path}: {err}")

    return findings


if __name__ == "__main__":
    certs_path = os.path.join(os.getcwd(), "testbed_repo", "certs")
    results = scan_certificates(certs_path)
    print(f"[+] Dynamic scan complete. Parsed {len(results)} certificate items.")