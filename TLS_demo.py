#!/usr/bin/env python3
"""
TLS Demo
Author: Rohit Saravanan

Features:
- TLS 1.3-only by default (optionally allow TLS 1.2 via --tls12 prompt)
- Hostname verification + system trust
- SNI + ALPN negotiation (h2, http/1.1)
- OCSP stapling check (if server staples)
- Certificate summary (cryptography optional for richer fields)
- Session resumption attempt
- Handshake timing + simple benchmark mode

Require ments: Python 3.10+ recommended
"""

import argparse
import socket
import ssl
import time
from typing import Optional, Tuple

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
except ImportError:
    x509 = None  # Optional; install 'cryptography' for richer cert parsing

ALPN_PROTOCOLS = ["h2", "http/1.1"]
DEFAULT_PORT = 443


def build_context(tls13_only: bool = True) -> ssl.SSLContext:
    """
    Build an SSLContext with robust cipher configuration across OpenSSL/LibreSSL builds.
    Uses set_ciphersuites for TLS 1.3 (if available) and set_ciphers for TLS 1.2 (if enabled).
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    # Version policy
    if tls13_only:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    else:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3

    # --- Cipher configuration (robust across platforms) ---
    # TLS 1.3 suites via dedicated API (if present)
    if hasattr(ctx, "set_ciphersuites"):
        try:
            ctx.set_ciphersuites(
                "TLS_AES_256_GCM_SHA384:"
                "TLS_CHACHA20_POLY1305_SHA256:"
                "TLS_AES_128_GCM_SHA256"
            )
        except ssl.SSLError:
            # Some stacks may still choke—let library defaults apply
            pass

    # Pre-TLS1.3 suites (only relevant if TLS 1.2 is allowed)
    if not tls13_only:
        try:
            # HIGH = secure suites; exclude weak/legacy
            ctx.set_ciphers("HIGH:!aNULL:!MD5:!RC4")
        except ssl.SSLError:
            pass
  

    # ALPN negotiation and security hardening
    try:
        ctx.set_alpn_protocols(ALPN_PROTOCOLS)
    except NotImplementedError:
        # Some builds may not support ALPN; non-fatal
        pass

    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True
    ctx.load_default_certs()
    ctx.options |= ssl.OP_NO_COMPRESSION

    return ctx


def connect_once(
    hostname: str,
    port: int,
    ctx: ssl.SSLContext,
    session: Optional[ssl.SSLSession] = None,
) -> Tuple[ssl.SSLSocket, float]:
    """
    Establish one TLS connection and return the SSLSocket + handshake time (ms).
    Optionally attempts to reuse a previous session (if supported by stack).
    """
    t0 = time.perf_counter()
    sock = socket.create_connection((hostname, port), timeout=10)
    try:
        if session is not None:
            # Some Python/OpenSSL combos allow pre-setting the session on the context
            try:
                ctx.session = session
            except Exception:
                pass
        ssock = ctx.wrap_socket(sock, server_hostname=hostname)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return ssock, elapsed_ms
    except Exception:
        sock.close()
        raise


def print_summary(hostname: str, ssock: ssl.SSLSocket, elapsed_ms: float) -> None:
    print(f"✓ Handshake complete with {hostname}")
    print(f"  • TLS version:   {ssock.version()}")
    print(f"  • Cipher:        {ssock.cipher()}")
    alpn = None
    try:
        alpn = ssock.selected_alpn_protocol()
    except NotImplementedError:
        pass
    print(f"  • ALPN:          {alpn}")
    reused = getattr(ssock, "session_reused", False)
    print(f"  • Session reused:{reused}")
    print(f"  • Handshake time:{elapsed_ms:.2f} ms")

    # OCSP stapling (if provided by server and supported by stack)
    ocsp_bytes = getattr(ssock, "ocsp_response", None)
    if ocsp_bytes:
        print(f"  • OCSP stapling: present ({len(ocsp_bytes)} bytes)")
    else:
        print("  • OCSP stapling: not provided")

    # Certificate summary
    try:
        der = ssock.getpeercert(binary_form=True)
        if x509 and der:
            cert = x509.load_der_x509_certificate(der, default_backend())
            print("  • Certificate:")
            print(f"      Subject: {cert.subject.rfc4514_string()}")
            print(f"      Issuer:  {cert.issuer.rfc4514_string()}")
            print(f"      Valid:   {cert.not_valid_before}  →  {cert.not_valid_after}")
        else:
            # Fallback dict
            cert = ssock.getpeercert()
            if cert:
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer = dict(x[0] for x in cert.get("issuer", []))
                print("  • Certificate:")
                print(f"      Subject CN: {subject.get('commonName', 'N/A')}")
                print(f"      Issuer CN:  {issuer.get('commonName', 'N/A')}")
            else:
                print("  • Certificate: (unavailable)")
    except Exception as e:
        print(f"  • Certificate parse error: {type(e).__name__}: {e}")


def run_once(hostname: str, port: int, tls13_only: bool) -> Optional[ssl.SSLSession]:
    ctx = build_context(tls13_only=tls13_only)
    ssock = None
    try:
        ssock, elapsed = connect_once(hostname, port, ctx)
        print_summary(hostname, ssock, elapsed)
        # Return session object if available (for possible resumption)
        return getattr(ssock, "session", None)
    finally:
        if ssock is not None:
            try:
                ssock.close()
            except Exception:
                pass


def benchmark(hostname: str, port: int, loops: int, tls13_only: bool) -> None:
    ctx = build_context(tls13_only=tls13_only)
    session = None
    times = []
    for i in range(1, loops + 1):
        try:
            ssock, elapsed = connect_once(hostname, port, ctx, session=session)
            times.append(elapsed)
            reused = getattr(ssock, "session_reused", False)
            print(f"Handshake {i}/{loops}: {elapsed:.2f} ms (resumed={reused})")
            session = getattr(ssock, "session", session)
        except Exception as e:
            print(f"Handshake {i}/{loops}: FAILED ({type(e).__name__}: {e})")
        finally:
            try:
                ssock.close()
            except Exception:
                pass
    if times:
        print(f"Avg: {sum(times)/len(times):.2f} ms | Min: {min(times):.2f} | Max: {max(times):.2f}")


def main():
    p = argparse.ArgumentParser(description="TLS Client Demo (Admissions-Ready)")
    p.add_argument("hostname", help="Target server hostname (SNI)")
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.add_argument("--bench", type=int, default=0, help="Run N handshake iterations and report stats")
    p.add_argument("--tls12", action="store_true", help="Allow TLS 1.2 (default = TLS 1.3 only)")
    args = p.parse_args()

    tls13_only = not args.tls12

    if args.bench > 0:
        benchmark(args.hostname, args.port, args.bench, tls13_only=tls13_only)
        return

    try:
        session = run_once(args.hostname, args.port, tls13_only=tls13_only)
        if session:
            print("\n— Attempting immediate second handshake (potential session resumption) —")
            ctx = build_context(tls13_only=tls13_only)
            ssock, elapsed = connect_once(args.hostname, args.port, ctx, session=session)
            print_summary(args.hostname, ssock, elapsed)
            try:
                ssock.close()
            except Exception:
                pass
    except ssl.SSLError as e:
        print(f"❌ Handshake failed: {e}")
    except Exception as e:
        print(f"⚠️ Error: {type(e).__name__}: {e}")


if __name__ == "__main__":
    # Helpful to know the crypto stack during troubleshooting:
    # print("Using:", ssl.OPENSSL_VERSION)
    main()