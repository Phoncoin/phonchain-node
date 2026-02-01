# phonchain-node (PoP-S4.1)

Reference **gateway / core node implementation** for the **Phonchain mainnet**,
secured by real smartphones via **Proof-of-Phone Secure v4.1 (PoP-S4.1)**.

This repository contains the **reference node software** (gateway + core modes).
The **canonical protocol definitions, bootstrap rules, and mainnet anchors**
are published separately and are mandatory for network identity.

---

## Canonical reference (MANDATORY)

Protocol specification, bootstrap rules and genesis anchors:

👉 https://github.com/Phoncoin/phoncoin

**Any chain with a different genesis hash is NOT the Phonchain mainnet.**

---

## Modes

### Gateway node (public)
- Serves public HTTPS endpoints (wallets / explorer clients / public API)
- **Open ports:** 80 / 443
- App API stays **private** on `127.0.0.1:5000` behind Nginx reverse proxy

### Core node (private)
- Not intended to be public-facing
- **No public ports**
- API may listen on `127.0.0.1:5000` for local admin / private network usage only
- If remote access is needed: **VPN or firewall whitelist** (trusted gateway IPs)

> ✅ Important: `127.0.0.1:5000` is **not public**.  
> It is reachable **only from the same server**.

---

## Requirements

- Linux (Ubuntu 20.04+ recommended)
- Python 3.9+
- Public IPv4 (gateway nodes only)
- A domain name + TLS (recommended for gateway)

---

## Network ports

### Gateway (public)
- TCP 80 / 443 open to the Internet
- Python/Gunicorn binds to **127.0.0.1:5000** only

### Core (private)
- No Internet-facing ports
- If you *must* allow remote API access, do it via:
  - VPN (recommended), or
  - strict firewall whitelist (trusted gateway IPs only)

---

## Quick start (Gateway)

### 1) System dependencies
```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip nginx
