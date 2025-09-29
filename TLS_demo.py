"""
TLS 1.2 Demo Connection
Author: Rohit Saravanan

This script demonstrates how to force a TLS 1.2 connection
to a server and prints out the negotiated protocol and cipher.
"""

import socket
import ssl

# Host and port for testing (Google supports both TLS 1.2 and 1.3)
HOST = "www.google.com"
PORT = 443

def connect_tls12(host: str, port: int = 443):
    # Create a default SSL context (system CAs, secure defaults)
    context = ssl.create_default_context()

    # Force TLS version to 1.2 only
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2

    # Establish TCP connection
    with socket.create_connection((host, port)) as sock:
        # Wrap TCP in TLS
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            print("✅ Connected using:", ssock.version())   # should say TLSv1.2
            print("🔒 Cipher suite:", ssock.cipher())

if __name__ == "__main__":
    connect_tls12(HOST, PORT)
