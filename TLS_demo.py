"""
TLS 1.2 & TLS 1.3 Connection Demo
Author: Rohit Saravanan

Enhancements:
- Supports both TLS 1.2 and TLS 1.3 connections.
- Prints protocol, cipher suite, and certificate details.
- Measures connection time for performance awareness.
- Handles handshake errors gracefully.
"""

import socket
import ssl
from datetime import datetime, timezone
import time

hostname = "www.google.com"
port = 443

# List of protocol versions to test
protocols = {
    "TLS 1.2": ssl.PROTOCOL_TLSv1_2,
    "TLS 1.3": ssl.PROTOCOL_TLS_CLIENT,  # Negotiates highest available (TLS 1.3 if supported)
}

for name, protocol in protocols.items():
    print(f"\n=== Attempting {name} connection to {hostname}:{port} ===")
    context = ssl.SSLContext(protocol)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_default_certs()

    try:
        start_time = time.time()
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                duration = (time.time() - start_time) * 1000  # in ms

                # TLS details
                print(f"🔐 Protocol: {ssock.version()}")
                print(f"   ➤ Cipher Suite: {ssock.cipher()}")
                print(f"   ➤ Handshake Time: {duration:.2f} ms")

                # Certificate details
                cert = ssock.getpeercert()
                subject = dict(x[0] for x in cert["subject"])
                issuer = dict(x[0] for x in cert["issuer"])
                expiry = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_left = (expiry - datetime.now(timezone.utc)).days

                print(f"   ➤ Certificate Issued To: {subject.get('commonName', 'N/A')}")
                print(f"   ➤ Certificate Issued By: {issuer.get('commonName', 'N/A')}")
                print(f"   ➤ Certificate Expiry: {expiry} (in {days_left} days)")
    except ssl.SSLError as e:
        print(f"❌ {name} handshake failed: {e}")
    except Exception as e:
        print(f"⚠️ Error during {name} connection: {e}")
