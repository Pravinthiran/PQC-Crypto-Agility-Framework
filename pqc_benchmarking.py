# pqc_benchmarking.py
import json
import os
import sys
import time
import pandas as pd
import psutil

# Ensure liboqs Windows DLL paths
dll_dir = os.path.abspath(os.path.join(os.getcwd(), "liboqs", "install", "bin"))
if os.path.exists(dll_dir):
    os.environ["OQS_DIR"] = os.path.abspath(os.path.join(os.getcwd(), "liboqs", "install"))
    if hasattr(os, "add_dll_directory"):
        os.add_dll_directory(dll_dir)

import oqs
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


class PQCPerformanceBenchmark:
    """Job 4: Tracks latency, memory footprint, and CPU overhead for PQC and classical primitives."""

    def __init__(self, iterations: int = 100):
        self.iterations = iterations
        self.process = psutil.Process(os.getpid())
        self.results = []

    def _get_ram_kb(self) -> float:
        return self.process.memory_info().rss / 1024.0

    def benchmark_kem(self, mechanism: str = "ML-KEM-768"):
        print(f"[*] Benchmarking KEM: {mechanism} ({self.iterations} iterations)...")
        keygen_times = []
        encap_times = []
        decap_times = []

        ram_before = self._get_ram_kb()
        cpu_start = time.process_time()

        for _ in range(self.iterations):
            # 1. Keygen
            t0 = time.perf_counter_ns()
            with oqs.KeyEncapsulation(mechanism) as receiver:
                pk = receiver.generate_keypair()
                t1 = time.perf_counter_ns()

                # 2. Encap
                with oqs.KeyEncapsulation(mechanism) as sender:
                    ct, s_secret = sender.encap_secret(pk)
                    t2 = time.perf_counter_ns()

                # 3. Decap
                r_secret = receiver.decap_secret(ct)
                t3 = time.perf_counter_ns()

            keygen_times.append((t1 - t0) / 1e6)  # to ms
            encap_times.append((t2 - t1) / 1e6)
            decap_times.append((t3 - t2) / 1e6)

        cpu_total = (time.process_time() - cpu_start) * 1000  # ms
        ram_after = self._get_ram_kb()

        avg_keygen = sum(keygen_times) / self.iterations
        avg_encap = sum(encap_times) / self.iterations
        avg_decap = sum(decap_times) / self.iterations
        total_cycle = avg_keygen + avg_encap + avg_decap

        record = {
            "category": "Key Encapsulation (KEM)",
            "standard": "FIPS 203",
            "primitive": mechanism,
            "iterations": self.iterations,
            "keygen_latency_ms": round(avg_keygen, 4),
            "encap_latency_ms": round(avg_encap, 4),
            "decap_latency_ms": round(avg_decap, 4),
            "total_cycle_ms": round(total_cycle, 4),
            "public_key_bytes": len(pk),
            "ciphertext_or_sig_bytes": len(ct),
            "cpu_time_total_ms": round(cpu_total, 2),
            "ram_delta_kb": round(ram_after - ram_before, 2)
        }
        self.results.append(record)
        return record

    def benchmark_sig(self, mechanism: str, standard: str):
        print(f"[*] Benchmarking Signature: {mechanism} ({self.iterations} iterations)...")
        payload = b"CRQC Agility Benchmarking Payload Evaluation"
        keygen_times = []
        sign_times = []
        verify_times = []

        ram_before = self._get_ram_kb()
        cpu_start = time.process_time()

        for _ in range(self.iterations):
            # 1. Keygen
            t0 = time.perf_counter_ns()
            with oqs.Signature(mechanism) as signer:
                pk = signer.generate_keypair()
                t1 = time.perf_counter_ns()

                # 2. Sign
                sig = signer.sign(payload)
                t2 = time.perf_counter_ns()

            # 3. Verify
            with oqs.Signature(mechanism) as verifier:
                verifier.verify(payload, sig, pk)
                t3 = time.perf_counter_ns()

            keygen_times.append((t1 - t0) / 1e6)
            sign_times.append((t2 - t1) / 1e6)
            verify_times.append((t3 - t2) / 1e6)

        cpu_total = (time.process_time() - cpu_start) * 1000
        ram_after = self._get_ram_kb()

        avg_keygen = sum(keygen_times) / self.iterations
        avg_sign = sum(sign_times) / self.iterations
        avg_verify = sum(verify_times) / self.iterations
        total_cycle = avg_keygen + avg_sign + avg_verify

        record = {
            "category": "Digital Signature",
            "standard": standard,
            "primitive": mechanism,
            "iterations": self.iterations,
            "keygen_latency_ms": round(avg_keygen, 4),
            "encap_latency_ms": round(avg_sign, 4),    # Mapped to Sign
            "decap_latency_ms": round(avg_verify, 4),  # Mapped to Verify
            "total_cycle_ms": round(total_cycle, 4),
            "public_key_bytes": len(pk),
            "ciphertext_or_sig_bytes": len(sig),
            "cpu_time_total_ms": round(cpu_total, 2),
            "ram_delta_kb": round(ram_after - ram_before, 2)
        }
        self.results.append(record)
        return record

    def benchmark_classical_rsa(self):
        print(f"[*] Benchmarking Classical Baseline: RSA-2048 ({self.iterations} iterations)...")
        payload = b"CRQC Agility Benchmarking Payload Evaluation"
        keygen_times = []
        sign_times = []
        verify_times = []

        ram_before = self._get_ram_kb()
        cpu_start = time.process_time()

        for _ in range(self.iterations):
            # Keygen
            t0 = time.perf_counter_ns()
            priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            pub = priv.public_key()
            t1 = time.perf_counter_ns()

            # Sign
            sig = priv.sign(payload, padding.PKCS1v15(), hashes.SHA256())
            t2 = time.perf_counter_ns()

            # Verify
            pub.verify(sig, payload, padding.PKCS1v15(), hashes.SHA256())
            t3 = time.perf_counter_ns()

            keygen_times.append((t1 - t0) / 1e6)
            sign_times.append((t2 - t1) / 1e6)
            verify_times.append((t3 - t2) / 1e6)

        cpu_total = (time.process_time() - cpu_start) * 1000
        ram_after = self._get_ram_kb()

        avg_keygen = sum(keygen_times) / self.iterations
        avg_sign = sum(sign_times) / self.iterations
        avg_verify = sum(verify_times) / self.iterations

        record = {
            "category": "Classical Baseline",
            "standard": "PKCS#1 v2.2",
            "primitive": "RSA-2048",
            "iterations": self.iterations,
            "keygen_latency_ms": round(avg_keygen, 4),
            "encap_latency_ms": round(avg_sign, 4),
            "decap_latency_ms": round(avg_verify, 4),
            "total_cycle_ms": round(avg_keygen + avg_sign + avg_verify, 4),
            "public_key_bytes": 270,   # DER encoded approx
            "ciphertext_or_sig_bytes": len(sig),
            "cpu_time_total_ms": round(cpu_total, 2),
            "ram_delta_kb": round(ram_after - ram_before, 2)
        }
        self.results.append(record)
        return record

    def run_suite(self):
        print("=" * 70)
        print("      PQC AGILITY FRAMEWORK: PERFORMANCE BENCHMARKING SUITE")
        print("=" * 70)

        # 1. Classical Baseline
        self.benchmark_classical_rsa()

        # 2. FIPS 203 KEM
        self.benchmark_kem("ML-KEM-768")

        # 3. FIPS 204 Lattice Sig
        self.benchmark_sig("ML-DSA-65", "FIPS 204")

        # 4. FIPS 205 Stateless Hash Sig (lower iteration count as SLH-DSA is computationally heavier)
        original_iter = self.iterations
        self.iterations = min(15, self.iterations)
        self.benchmark_sig("SLH_DSA_PURE_SHAKE_128S", "FIPS 205")
        self.iterations = original_iter

        # Format and display DataFrame
        df = pd.DataFrame(self.results)
        print("\n" + "=" * 70)
        print("                  BENCHMARK EVALUATION SUMMARY")
        print("=" * 70)
        display_cols = [
            "primitive",
            "standard",
            "keygen_latency_ms",
            "encap_latency_ms",
            "decap_latency_ms",
            "public_key_bytes",
            "ciphertext_or_sig_bytes",
            "ram_delta_kb"
        ]
        print(df[display_cols].to_string(index=False))

        # Exports
        csv_path = "pqc_benchmark_metrics.csv"
        json_path = "pqc_benchmark_metrics.json"
        df.to_csv(csv_path, index=False)
        df.to_json(json_path, orient="records", indent=2)

        print("\n" + "=" * 70)
        print(f"[+] Benchmarking results saved:")
        print(f"    - CSV  : {os.path.abspath(csv_path)}")
        print(f"    - JSON : {os.path.abspath(json_path)}")
        print("=" * 70)
        return df


if __name__ == "__main__":
    bench = PQCPerformanceBenchmark(iterations=50)
    bench.run_suite()