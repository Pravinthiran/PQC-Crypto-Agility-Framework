# network_traffic_scanner.py
import socket
import ssl
from OpenSSL import crypto


class NetworkCryptoScanner:
  """Discovers active cryptographic assets negotiated across network endpoints."""

  def __init__(self, target_host="127.0.0.1", target_port=8443):
    self.host = target_host
    self.port = target_port

  def scan_endpoint(self):
    print("=" * 68)
    print(f"   ACTIVE NETWORK DISCOVERY: PROBING {self.host}:{self.port}")
    print("=" * 68)

    discovered_assets = []

    try:
      # 1. Establish SSL/TLS connection using Python standard library
      ctx = ssl.create_default_context()
      ctx.check_hostname = False
      ctx.verify_mode = ssl.CERT_NONE

      with socket.create_connection((self.host, self.port), timeout=5.0) as sock:
        with ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
          cipher = ssock.cipher()  # (cipher_name, tls_version, secret_bits)
          peer_cert_der = ssock.getpeercert(binary_form=True)

          cipher_name = cipher[0]
          tls_version = cipher[1]
          cipher_bits = cipher[2]

          print(f"[+] Handshake Established with {self.host}:{self.port}")
          print(f"    - Protocol Version  : {tls_version}")
          print(
              f"    - Active Cipher     : {cipher_name} ({cipher_bits}-bit)"
          )

          discovered_assets.append({
              "bom_ref": f"net-cipher-{self.port}",
              "component_name": f"Network-Transit-Cipher-{cipher_name}",
              "asset_type": "Network Transit Protocol",
              "primitive_family": "Cipher Suite / Key Exchange",
              "algorithm": cipher_name,
              "key_size_or_curve": f"{cipher_bits} bits",
              "location": f"tcp://{self.host}:{self.port}",
              "discovery_mode": "Dynamic Network Traffic Probe",
          })

          # 2. Parse peer certificate if presented
          if peer_cert_der:
            x509 = crypto.load_certificate(
                crypto.FILETYPE_ASN1, peer_cert_der
            )
            pubkey = x509.get_pubkey()
            pubkey_type = pubkey.type()

            if pubkey_type == crypto.TYPE_RSA:
              key_type = "RSA"
            elif pubkey_type == crypto.TYPE_DSA:
              key_type = "DSA"
            elif pubkey_type == 408:  # EVP_PKEY_EC
              key_type = "ECC"
            else:
              key_type = "UNKNOWN"

            sig_alg = x509.get_signature_algorithm().decode("utf-8")
            key_bits = pubkey.bits()

            print(f"[+] Wire Certificate Harvested:")
            print(f"    - Public Key Type   : {key_type} ({key_bits} bits)")
            print(f"    - Signature Alg     : {sig_alg}")

            discovered_assets.append({
                "bom_ref": f"net-cert-{self.port}",
                "component_name": f"Network-Presented-Cert-{key_type}",
                "asset_type": "X.509 Wire Certificate",
                "primitive_family": "Public Key Infrastructure (PKI)",
                "algorithm": key_type,
                "key_size_or_curve": f"{key_bits} bits",
                "location": f"tcp://{self.host}:{self.port} (Wire Handshake)",
                "discovery_mode": "Dynamic Network Traffic Probe",
            })

    except Exception as e:
      print(f"[-] Network scan note on {self.host}:{self.port}: {e}")

    return discovered_assets


if __name__ == "__main__":
  scanner = NetworkCryptoScanner("127.0.0.1", 8443)
  results = scanner.scan_endpoint()
  print(f"\n[+] Total Network Assets Found: {len(results)}")