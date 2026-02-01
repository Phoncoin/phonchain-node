# phonchain-node (PoP-S4.1)

Reference **gateway / core node implementation** for the **Phonchain mainnet**,
secured by real smartphones via **Proof-of-Phone Secure v4.1 (PoP-S4.1)**.

✅ This repository contains the **reference node software** (gateway + core modes).  
⚠️ This repository does **NOT** define consensus rules or network identity.

Canonical protocol rules, bootstrap anchors and genesis parameters are defined
separately and are **mandatory**.

---

## Canonical reference (MANDATORY)

Protocol specification, bootstrap rules and genesis anchors:

👉 https://github.com/Phoncoin/phoncoin

**Any chain with a different genesis hash is NOT the Phonchain mainnet.**

---

## Node modes

### Gateway node (public)

Gateway nodes provide **public HTTPS access** to the Phonchain network.

- Public-facing infrastructure
- **Open ports:** 80 / 443
- Nginx handles HTTPS and proxies requests
- Node API remains **PRIVATE** on `127.0.0.1:5000` (localhost only)

### Core node (private)

Core nodes are **private infrastructure components**.

- **No public ports**
- API must remain local-only (`127.0.0.1:5000`)
- If remote access is required:
  - VPN (recommended), or
  - strict firewall whitelist (trusted gateway IPs only)

> ✅ Important: `127.0.0.1:5000` is **NOT public**.  
> It is reachable **only from the same server**.

---

## Requirements

- Linux (Ubuntu 20.04+ recommended)
- Python 3.9+
- Public IPv4 + domain name (gateway nodes only)

---

## Security notes

⚠️ **NEVER commit or expose:**

- `.env` files
- database files (`*.db`, `*.sqlite`, `*-wal`, `*-shm`)
- wallets or private keys
- logs or backups

This repository contains **reference software and configuration only**.  
Each operator is responsible for securing their infrastructure.

---

## Gateway installation (recommended public setup)

### 1) System dependencies
```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip nginx
