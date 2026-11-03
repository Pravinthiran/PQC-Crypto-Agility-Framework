# generate_tier2_pcaps.py
import os
import struct
import time
from scapy.all import IP, TCP, Raw, wrpcap

OUTPUT_DIR = "network_traces"
os.makedirs(OUTPUT_DIR, exist_ok=True)


def build_tls_record(content_type: int, version: tuple, payload: bytes) -> bytes:
  """Constructs a standard TLS Record Layer frame."""
  return (
      struct.pack("!BHH", content_type, (version[0] << 8) | version[1], len(payload))
      + payload
  )


def create_rsa_trace():
  """Generates a synthetic TLS 1.2 Handshake trace negotiating RSA-2048."""
  pcap_path = os.path.join(OUTPUT_DIR, "rsa_handshake.pcap")
  packets = []

  base_ip = IP(src="192.168.1.50", dst="192.168.1.100")
  base_tcp = TCP(sport=54321, dport=443, flags="PA", seq=1000, ack=2000)

  # 1. ClientHello (advertising RSA cipher suites)
  client_hello_payload = b"\x01\x00\x00\x65\x03\x03" + (b"\x11" * 32) + b"\x00\x00\x02\x00\x35\x01\x00"
  pkt1 = base_ip / base_tcp / Raw(load=build_tls_record(22, (3, 3), client_hello_payload))
  pkt1.time = time.time()
  packets.append(pkt1)

  # 2. ServerHello + Certificate (RSA-2048 public key ~256 bytes)
  # Simulated RSA Certificate payload size: ~1,400 bytes (fits standard 1500 MTU without fragmentation)
  rsa_cert_body = b"\x02\x00\x00\x46\x03\x03" + (b"\x22" * 32) + (b"\xAA" * 1200)
  pkt2 = IP(src="192.168.1.100", dst="192.168.1.50") / TCP(sport=443, dport=54321, flags="PA", seq=2000, ack=1150) / Raw(load=build_tls_record(22, (3, 3), rsa_cert_body))
  pkt2.time = pkt1.time + 0.015  # 15 ms network round-trip
  packets.append(pkt2)

  # 3. ClientKeyExchange (Encrypted Pre-Master Secret: 256 bytes for RSA-2048)
  client_kex_body = b"\x10\x00\x01\x00" + (b"\xBB" * 256)
  pkt3 = base_ip / TCP(sport=54321, dport=443, flags="PA", seq=1150, ack=3250) / Raw(load=build_tls_record(22, (3, 3), client_kex_body))
  pkt3.time = pkt2.time + 0.012  # 12 ms client computation & transit
  packets.append(pkt3)

  # 4. Finished / Session Established
  pkt4 = IP(src="192.168.1.100", dst="192.168.1.50") / TCP(sport=443, dport=54321, flags="PA", seq=3250, ack=1410) / Raw(load=build_tls_record(20, (3, 3), b"\x01") + build_tls_record(22, (3, 3), b"\x14\x00\x00\x0c" + b"\xCC" * 12))
  pkt4.time = pkt3.time + 0.010
  packets.append(pkt4)

  wrpcap(pcap_path, packets)
  print(f"[+] Successfully generated: {pcap_path} (4 packets, Classical RSA-2048 Handshake)")


def create_pqc_kem_trace():
  """Generates a synthetic TLS Handshake negotiating ML-KEM-768 (FIPS 203).

  Demonstrates packet fragmentation caused by 1184-byte public key + 1088-byte ciphertext.
  """
  pcap_path = os.path.join(OUTPUT_DIR, "pqc_kem_handshake.pcap")
  packets = []

  base_ip = IP(src="192.168.1.50", dst="192.168.1.100")
  base_tcp = TCP(sport=54322, dport=443, flags="PA", seq=5000, ack=6000)

  # 1. ClientHello with ML-KEM-768 Key Share (1184 bytes PK + TLS overhead ~ 1250 bytes)
  client_hello_pqc = b"\x01\x00\x04\xec\x03\x04" + (b"\x33" * 32) + (b"\xDE" * 1184)
  pkt1 = base_ip / base_tcp / Raw(load=build_tls_record(22, (3, 3), client_hello_pqc))
  pkt1.time = time.time()
  packets.append(pkt1)

  # 2. ServerHello + ML-KEM Encapsulated Ciphertext (1088 bytes)
  pqc_server_kex = b"\x02\x00\x04\x60\x03\x04" + (b"\x44" * 32) + (b"\xEE" * 1088)
  pkt2 = IP(src="192.168.1.100", dst="192.168.1.50") / TCP(sport=443, dport=54322, flags="PA", seq=6000, ack=6260) / Raw(load=build_tls_record(22, (3, 3), pqc_server_kex))
  pkt2.time = pkt1.time + 0.019  # 19 ms
  packets.append(pkt2)

  # 3. Finished / Session Established
  pkt3 = base_ip / TCP(sport=54322, dport=443, flags="PA", seq=6260, ack=7150) / Raw(load=build_tls_record(22, (3, 3), b"\x14\x00\x00\x20" + b"\xFF" * 32))
  pkt3.time = pkt2.time + 0.008
  packets.append(pkt3)

  wrpcap(pcap_path, packets)
  print(f"[+] Successfully generated: {pcap_path} (3 packets, Post-Quantum ML-KEM-768 Handshake)")


if __name__ == "__main__":
  create_rsa_trace()
  create_pqc_kem_trace()