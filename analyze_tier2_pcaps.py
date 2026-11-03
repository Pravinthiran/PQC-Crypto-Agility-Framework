# analyze_tier2_pcaps.py
import os
import json
import pandas as pd
from scapy.all import rdpcap, TCP, Raw

TRACES_DIR = "network_traces"

def inspect_pcap(filepath: str, label: str):
    """Parses a pcap file using Scapy to extract handshake duration and wire bytes."""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"[-] PCAP file not found: {filepath}")

    packets = rdpcap(filepath)
    if len(packets) == 0:
        raise ValueError(f"[-] Empty PCAP trace: {filepath}")

    total_wire_bytes = sum(len(pkt) for pkt in packets)
    payload_bytes = sum(len(pkt[Raw].load) for pkt in packets if Raw in pkt)
    packet_count = len(packets)

    # Frame timestamps (first packet to last packet)
    t_start = float(packets[0].time)
    t_end = float(packets[-1].time)
    handshake_duration_ms = round((t_end - t_start) * 1000.0, 3)

    # Packet size distribution
    packet_sizes = [len(pkt) for pkt in packets]
    max_frame_bytes = max(packet_sizes)

    return {
        "primitive_negotiated": label,
        "packet_count": packet_count,
        "total_wire_bytes": total_wire_bytes,
        "total_payload_bytes": payload_bytes,
        "max_frame_size_bytes": max_frame_bytes,
        "handshake_duration_ms": handshake_duration_ms,
        "mtu_fragmentation_risk": "Yes (>1500B)" if max_frame_bytes > 1500 else "No (Fits MTU)"
    }

def run_tier2_network_proof():
    print("=" * 72)
    print("   TIER 2 PROOF: EMPIRICAL NETWORK & PACKET TRACE BENCHMARKING")
    print("=" * 72)

    rsa_path = os.path.join(TRACES_DIR, "rsa_handshake.pcap")
    pqc_path = os.path.join(TRACES_DIR, "pqc_kem_handshake.pcap")

    data = [
        inspect_pcap(rsa_path, "Classical RSA-2048 (TLS 1.2)"),
        inspect_pcap(pqc_path, "Post-Quantum ML-KEM-768 (FIPS 203)")
    ]

    df_net = pd.DataFrame(data)

    # Compute Differentials
    base_bytes = df_net.loc[df_net["primitive_negotiated"].str.contains("RSA"), "total_wire_bytes"].values[0]
    pqc_bytes = df_net.loc[df_net["primitive_negotiated"].str.contains("ML-KEM"), "total_wire_bytes"].values[0]
    wire_inflation_pct = round(((pqc_bytes - base_bytes) / base_bytes) * 100.0, 2)

    base_time = df_net.loc[df_net["primitive_negotiated"].str.contains("RSA"), "handshake_duration_ms"].values[0]
    pqc_time = df_net.loc[df_net["primitive_negotiated"].str.contains("ML-KEM"), "handshake_duration_ms"].values[0]
    latency_delta_ms = round(pqc_time - base_time, 3)

    print("\n[+] EXTRACTED EMPIRICAL WIRE METRICS:")
    print(df_net.to_string(index=False))

    print("\n[+] WIRE OVERHEAD & TRANSMISSION COMPARATIVE ANALYSIS:")
    print(f"    - Classical Wire Volume   : {base_bytes:,} Bytes")
    print(f"    - Post-Quantum Wire Volume: {pqc_bytes:,} Bytes")
    print(f"    - Net Wire Overhead Growth: +{wire_inflation_pct}%")
    print(f"    - Network Transit Delta   : {latency_delta_ms:+} ms")

    # Export datasets
    csv_out = "pqc_network_metrics.csv"
    json_out = "pqc_network_metrics.json"
    df_net.to_csv(csv_out, index=False)
    df_net.to_json(json_out, orient="records", indent=2)

    print("\n" + "=" * 72)
    print(f"[+] Tier 2 Datasets Exported:")
    print(f"    - CSV  : {os.path.abspath(csv_out)}")
    print(f"    - JSON : {os.path.abspath(json_out)}")
    print("=" * 72)

if __name__ == "__main__":
    run_tier2_network_proof()