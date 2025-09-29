"""
TLS 1.2 Demo Connection (Iteration 2)
Author: Rohit Saravanan

Enhancements:
- Extracts TLS protocol and cipher suite.
- Retrieves certificate details (issuer, subject, expiry).
- Calculates days until certificate expiration using timezone-aware datetimes.
"""

import socket
import ssl
from datetime import datetime, timezone

# Target host/port for TLS test
hostname = "www.google.com"
port = 443

# Force TLS 1.2 context
context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.check_hostname = True
context.verify_mode = ssl.CERT_REQUIRED
context.load_default_certs()

with socket.create_connection((hostname, port)) as sock:
    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
        # TLS details
        protocol_version = ssock.version()
        cipher = ssock.cipher()

        # Certificate details
        cert = ssock.getpeercert()
        issued_to = dict(x[0] for x in cert.get("subject", ())).get("commonName", "N/A")
        issued_by = dict(x[0] for x in cert.get("issuer", ())).get("commonName", "N/A")

        # Handle expiry parsing
        not_after = cert.get("notAfter", None)
        if not_after:
            expiry_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            expiry_date = expiry_date.replace(tzinfo=timezone.utc)
            days_left = (expiry_date - datetime.now(timezone.utc)).days
        else:
            expiry_date = "Unknown"
            days_left = "N/A"

        # Output
        print(f"🔐 Connected to {hostname}:{port}")
        print(f"   ➤ TLS Protocol: {protocol_version}")
        print(f"   ➤ Cipher Suite: {cipher}")
        print(f"   ➤ Certificate Issued To: {issued_to}")
        print(f"   ➤ Certificate Issued By: {issued_by}")
        print(f"   ➤ Certificate Expiry: {expiry_date} (in {days_left} days)")

        # Warn if expiry is close
        if isinstance(days_left, int) and days_left < 30:
            print("⚠️  Certificate is expiring soon!")

