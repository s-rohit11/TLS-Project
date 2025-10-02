# 🔒 TLS Handshake Project (Python)

## 📌 Overview
This project demonstrates the **Transport Layer Security (TLS) Handshake** using Python’s built-in `ssl` library.  
It goes beyond a basic client–server setup by supporting **TLS 1.3 (default)** and optionally TLS 1.2, with added features like **hostname verification, SNI, ALPN negotiation, OCSP stapling checks, certificate parsing, and session resumption**.  
The project also includes a simple **benchmarking mode** to measure handshake times across (n) iterations.  

## ⚙️ Features
- ✅ TLS 1.3-only by default (with optional TLS 1.2 via `--tls12`)  
- ✅ Hostname verification + system trust store  
- ✅ Server Name Indication (SNI) + ALPN negotiation (`h2`, `http/1.1`)  
- ✅ OCSP stapling detection (if server provides it)  
- ✅ Certificate parsing and summary (subject, issuer, validity)  
- ✅ Session resumption support (if server stack allows)  
- ✅ Handshake timing and simple benchmark mode (`--bench N`)  

## 📂 Project Structure
- `TLS_demo.py` → Main client program (this file)
- `negative-tests.py`  → Negative test scenarios (expired cert, wrong host, etc.) 
