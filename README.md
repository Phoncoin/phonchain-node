# phonchain-node (PoP-S4.1)

Reference **gateway / core node implementation** for the **Phonchain mainnet**,
secured by real smartphones via **Proof-of-Phone Secure v4.1 (PoP-S4.1)**.

✅ This repository contains the **reference node software** (gateway + core modes).  
⚠️ This repository does **NOT** define consensus rules or network identity.

Canonical protocol rules, bootstrap anchors and genesis parameters are defined separately
and are **mandatory**.

---

## Canonical reference (MANDATORY)

Protocol specification, bootstrap rules and genesis anchors:

👉 https://github.com/Phoncoin/phoncoin

**Any chain with a different genesis hash is NOT the Phonchain mainnet.**

---

## Node modes

### Gateway node (public)
Gateway nodes provide **public HTTPS access** to the network.

- **Public ports:** 80 / 443
- Nginx is public and proxies requests to the node API
- Node API stays **private** on `127.0.0.1:5000` (localhost only)

### Core node (private)
Core nodes are private infrastructure components.

- **No public ports**
- API should remain local-only (`127.0.0.1:5000`)
- If remote access is required: use **VPN** or strict **firewall whitelist**
  (trusted gateway IPs only)

> ✅ Important: `127.0.0.1:5000` is **not public**.  
> It is reachable **only from the same server**.

---

## Requirements

- Linux (Ubuntu 20.04+ recommended)
- Python 3.9+
- Public IPv4 + domain name (gateway nodes only)

---

## Security notes

⚠️ NEVER commit or expose:
- `.env` files
- database files (`*.db`, `*.sqlite`, `*-wal`, `*-shm`)
- wallets / private keys
- logs / backups

---

## Gateway installation (recommended public setup)

### 1) System dependencies
```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip nginx
