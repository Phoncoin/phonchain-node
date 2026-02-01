# phonchain-node (PoP-S4.1)

Reference **gateway / core node implementation** for the
**Phonchain mainnet**, secured by real smartphones via
**Proof-of-Phone Secure v4.1 (PoP-S4.1)**.

This repository contains the **reference node software**.
Canonical protocol definitions and mainnet anchors are published separately.

---

## Canonical reference (MANDATORY)
Protocol specification, bootstrap rules and genesis anchors are defined here:

👉 https://github.com/Phoncoin/phoncoin

**Any chain with a different genesis hash is NOT the Phonchain mainnet.**

---

## Requirements
- Linux (Ubuntu 20.04+ recommended)
- Python 3.9+
- Public IPv4 (for gateway nodes)
- Open ports: `80 / 443 / 5000`

---

## Installation

### 1) System dependencies
```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip nginx
