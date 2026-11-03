# dynamic_traffic_testbed.py
import os
import ssl
import socket
import threading
import time

CERT_FILE = os.path.join("testbed_repo", "certs", "legacy_bank.crt")
KEY_FILE = os.path.join("testbed_repo", "certs", "legacy_bank.key")

def run_legacy_tls_server(host="127.0.0.1", port=8443):
    """Spins up a lightweight TLS server running legacy cipher configurations."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # Enable classical curves and cipher suites to emulate legacy infrastructure
    context.set_ciphers("ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:AES256-SHA")
    
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    else:
        print(f"[-] Certificates not found at {CERT_FILE}. Server exiting.")
        return

    bindsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bindsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    bindsocket.bind((host, port))
    bindsocket.listen(5)
    print(f"[+] [TESTBED] Legacy TLS Server listening on https://{host}:{port}")

    while True:
        try:
            newsocket, fromaddr = bindsocket.accept()
            conn = context.wrap_socket(newsocket, server_side=True)
            try:
                data = conn.recv(1024)
                if data:
                    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nLegacy TLS Enterprise Node")
            finally:
                conn.shutdown(socket.SHUT_RDWR)
                conn.close()
        except Exception:
            break

def trigger_mock_client_traffic(host="127.0.0.1", port=8443, iterations=3):
    """Simulates internal enterprise clients connecting to the server."""
    time.sleep(1) # Wait for server boot
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for i in range(iterations):
        try:
            with socket.create_connection((host, port), timeout=3) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    ssock.sendall(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
                    _ = ssock.recv(1024)
            time.sleep(0.5)
        except Exception as e:
            print(f"[-] Mock connection {i+1} failed: {e}")

if __name__ == "__main__":
    t = threading.Thread(target=run_legacy_tls_server, daemon=True)
    t.start()
    trigger_mock_client_traffic()
    print("[+] Testbed execution completed.")