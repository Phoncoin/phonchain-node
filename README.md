# phonchain-node (PoP-S4.1)

Reference **gateway / core node implementation** for the **Phonchain mainnet**,
secured by real smartphones via **Proof-of-Phone Secure v4.1 (PoP-S4.1)**.

This repository contains the **reference node software** (gateway + core modes).

⚠️ **This repository does NOT define the consensus or network identity.**  
Canonical protocol rules, bootstrap anchors and genesis parameters are
defined separately and are mandatory.

---

## Canonical reference (MANDATORY)

Protocol specification, bootstrap rules and genesis anchors:

👉 https://github.com/Phoncoin/phoncoin

**Any chain with a different genesis hash is NOT the Phonchain mainnet.**

---

## Node modes

### Gateway node (public)

Gateway nodes provide **public access** to the Phonchain network.

- Serves HTTPS endpoints (wallets, explorers, public API)
- **Open ports:** 80 / 443
- Python/Gunicorn API remains **private** on `127.0.0.1:5000`
- Nginx acts as a reverse proxy

### Core node (private)

Core nodes are **private infrastructure components**.

- Not intended to be public-facing
- **No public ports**
- API may listen on `127.0.0.1:5000` for local admin or internal usage only
- If remote access is required:
  - VPN (recommended), or
  - strict firewall whitelist (trusted gateway IPs only)

> ✅ Important: `127.0.0.1:5000` is **never public**.  
> It is reachable **only from the same server**.

---

## Requirements

- Linux (Ubuntu 20.04+ recommended)
- Python 3.9+
- Public IPv4 (gateway nodes only)
- Domain name + TLS certificate (recommended for gateways)

---

## Network ports

### Gateway (public)

- TCP ports **80 / 443** open to the Internet
- Python/Gunicorn binds to **127.0.0.1:5000** only

### Core (private)

- No Internet-facing ports
- Optional remote access via:
  - VPN (recommended)
  - or firewall whitelist (trusted gateway IPs only)

---

## Security notes

⚠️ **NEVER commit or expose:**

- `.env` files
- Database files (`*.db`, `*.sqlite`)
- Wallets or private keys
- Logs or backups

This repository contains **reference software and configuration only**.
Each operator is responsible for securing their infrastructure.

---

## Support & disclosure

For documentation and protocol rules, see the canonical repository:
👉 https://github.com/Phoncoin/phoncoin

For security issues, follow responsible disclosure procedures.
