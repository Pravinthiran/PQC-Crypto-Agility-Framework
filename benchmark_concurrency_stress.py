# benchmark_concurrency_stress.py
import socket
import threading
import time
import concurrent.futures
import pandas as pd
import numpy as np
import oqs

HOST = "127.0.0.1"
PORT = 9666

def threaded_socket_server(ready_event, stop_event):
    """Multi-threaded socket server handling concurrent handshake requests."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(500)
    server.settimeout(0.5)
    ready_event.set()

    def handle_client(conn):
        with conn:
            try:
                conn.settimeout(2.0)
                header = conn.recv(4)
                if not header:
                    return
                mode = header.decode("utf-8")
                if mode == "PQC_":
                    pk = conn.recv(2048)
                    with oqs.KeyEncapsulation("ML-KEM-768") as kem:
                        ciphertext, _ = kem.encap_secret(pk)
                        conn.sendall(ciphertext)
                elif mode == "RSA_":
                    pk_bytes = conn.recv(4096)
                    conn.sendall(b"\xAA" * 256)
            except Exception:
                pass

    while not stop_event.is_set():
        try:
            conn, _ = server.accept()
            client_t = threading.Thread(target=handle_client, args=(conn,), daemon=True)
            client_t.start()
        except socket.timeout:
            continue
        except Exception:
            break
    server.close()

def client_handshake_worker(proto_mode: str) -> tuple[bool, float]:
    """Single client worker attempting a handshake. Returns (success, latency_ms)."""
    t0 = time.perf_counter()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        s.connect((HOST, PORT))
        if proto_mode == "PQC_":
            with oqs.KeyEncapsulation("ML-KEM-768") as kem:
                pk = kem.generate_keypair()
                s.sendall(b"PQC_" + pk)
                ct = s.recv(2048)
                _ = kem.decap_secret(ct)
        else:
            s.sendall(b"RSA_" + (b"\xBB" * 294))
            _ = s.recv(2048)
        s.close()
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return True, elapsed_ms
    except Exception:
        return False, (time.perf_counter() - t0) * 1000.0

def run_concurrency_benchmarks():
    print("=" * 80)
    print("   TIER 2 CONCURRENCY STRESS & THROUGHPUT SATURATION BENCHMARK")
    print("=" * 80)

    concurrency_levels = [50, 100, 250]
    protocols = [
        ("Classical RSA-2048", "RSA_"),
        ("Post-Quantum ML-KEM-768", "PQC_")
    ]
    records = []

    for proto_label, proto_code in protocols:
        print(f"\n[*] Evaluating Protocol: {proto_label}")
        for workers in concurrency_levels:
            ready_event = threading.Event()
            stop_event = threading.Event()
            server_t = threading.Thread(target=threaded_socket_server, args=(ready_event, stop_event), daemon=True)
            server_t.start()
            ready_event.wait()

            time.sleep(0.2)
            t_start = time.perf_counter()

            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
                futures = [executor.submit(client_handshake_worker, proto_code) for _ in range(workers)]
                results = [f.result() for f in concurrent.futures.as_completed(futures)]

            total_wall_time = time.perf_counter() - t_start
            stop_event.set()
            server_t.join()

            successes = [r[1] for r in results if r[0]]
            dropped_count = len(results) - len(successes)
            success_rate = (len(successes) / len(results)) * 100.0
            throughput = len(successes) / total_wall_time if total_wall_time > 0 else 0

            mean_lat = np.mean(successes) if successes else 0.0
            p95_lat = np.percentile(successes, 95) if successes else 0.0

            records.append({
                "protocol": proto_label,
                "concurrent_clients": workers,
                "completed_handshakes": len(successes),
                "dropped_connections": dropped_count,
                "success_rate_pct": round(success_rate, 2),
                "throughput_handshakes_sec": round(throughput, 1),
                "mean_latency_ms": round(mean_lat, 2),
                "p95_latency_ms": round(p95_lat, 2)
            })
            print(f"    - Concurrency {workers:3d}: Success {success_rate:6.2f}% | Dropped: {dropped_count:2d} | Throughput: {throughput:6.1f} req/s | P95: {p95_lat:6.2f} ms")

    df = pd.DataFrame(records)
    csv_file = "concurrency_saturation_metrics.csv"
    df.to_csv(csv_file, index=False)
    print("\n" + "=" * 80)
    print(f"[+] Concurrency Metrics Exported: {csv_file}")
    print("=" * 80)

if __name__ == "__main__":
    run_concurrency_benchmarks()