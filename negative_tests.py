#!/usr/bin/env python3
"""
Simple negative/edge tests for the TLS client.
- Hostname mismatch should fail verification
- TLS 1.3 enforcement test
- Timeout on unroutable TEST-NET address
"""

import socket
import ssl
from TLS_demo import build_context, connect_once, DEFAULT_PORT


def hostname_mismatch_test(host="www.google.com"):
    ctx = build_context(tls13_only=True)
    try:
        with socket.create_connection((host, DEFAULT_PORT), timeout=5) as sock:
            # Intentionally wrong SNI to trigger hostname mismatch
            with ctx.wrap_socket(sock, server_hostname="example.com"):
                pass
        print("✗ Hostname mismatch: unexpectedly succeeded")
    except ssl.SSLCertVerificationError as e:
        print(f"✓ Hostname mismatch: expected failure ({e.verify_message})")
    except Exception as e:
        print(f"✓ Hostname mismatch: failed as expected ({type(e).__name__}: {e})")


def tls13_only_test(host="www.google.com"):
    ctx = build_context(tls13_only=True)
    ssock, _ = connect_once(host, DEFAULT_PORT, ctx)
    try:
        if ssock.version() == "TLSv1.3":
            print("✓ TLS 1.3 enforced")
        else:
            print(f"✗ Expected TLS 1.3, got {ssock.version()}")
    finally:
        try:
            ssock.close()
        except Exception:
            pass


def timeout_test(ip="203.0.113.1", port=443):
    # 203.0.113.0/24 is TEST-NET-3 (documentation-only, not routable)
    try:
        socket.create_connection((ip, port), timeout=1)
        print("✗ Timeout test: unexpectedly connected")
    except Exception as e:
        print(f"✓ Timeout test: failed to connect as expected ({type(e).__name__})")


if __name__ == "__main__":
    hostname_mismatch_test()
    tls13_only_test()
    timeout_test()
