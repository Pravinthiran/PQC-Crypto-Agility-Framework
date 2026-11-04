# benchmark_keystore_stress.py
import os
import time
import shutil
import warnings
import pandas as pd
from OpenSSL import crypto

# Silence cryptography/pyOpenSSL deprecation warnings during benchmark
warnings.filterwarnings("ignore", category=DeprecationWarning)

CERTS_DIR = "stress_test_certs"

def generate_sample_x509_der(serial: int) -> bytes:
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)
    cert = crypto.X509()
    cert.get_subject().C = "MY"
    cert.get_subject().O = "Enterprise Bank Corp"
    cert.get_subject().CN = f"service-{serial}.internal"
    cert.set_serial_number(serial)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha256')
    return crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)

def run_keystore_stress_evaluation():
    print("=" * 70)
    print("   TIER 3 EMPIRICAL TEST: 1,000 X.509 CERTIFICATE INGESTION BENCHMARK")
    print("=" * 70)
    
    os.makedirs(CERTS_DIR, exist_ok=True)
    count = 1000
    print(f"[*] Generating {count} actual X.509 DER certificates on disk...")
    for i in range(count):
        with open(os.path.join(CERTS_DIR, f"cert_{i:04d}.der"), "wb") as f:
            f.write(generate_sample_x509_der(i))

    print("[*] Benchmarking pyOpenSSL disk parsing throughput...")
    t0 = time.perf_counter()
    parsed_records = []
    
    files = [os.path.join(CERTS_DIR, f) for f in os.listdir(CERTS_DIR) if f.endswith(".der")]
    for fpath in files:
        with open(fpath, "rb") as f:
            buf = f.read()
        cert = crypto.load_certificate(crypto.FILETYPE_ASN1, buf)
        pubkey = cert.get_pubkey()
        parsed_records.append({
            "cn": cert.get_subject().CN,
            "algo": "RSA" if pubkey.type() == crypto.TYPE_RSA else "ECC",
            "bits": pubkey.bits()
        })
        
    t_elapsed = time.perf_counter() - t0
    throughput = count / t_elapsed

    df_keystore = pd.DataFrame([{
        "total_certificates_parsed": count,
        "format": "X.509 ASN.1 DER",
        "total_latency_seconds": round(t_elapsed, 3),
        "ingestion_throughput_certs_per_sec": round(throughput, 2)
    }])
    df_keystore.to_csv("keystore_stress_metrics.csv", index=False)

    print("\n" + "=" * 70)
    print(f"[+] Successfully parsed {len(parsed_records):,} X.509 certificates from disk!")
    print(f"    - Total Parsing Latency : {t_elapsed:.3f} seconds")
    print(f"    - Ingestion Throughput  : {throughput:.1f} certs/second")
    print(f"    - Saved Summary to      : keystore_stress_metrics.csv")
    print("=" * 70)

    shutil.rmtree(CERTS_DIR)

if __name__ == "__main__":
    run_keystore_stress_evaluation()