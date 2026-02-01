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

~~~bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip nginx
~~~

### 2) Create system user and install directory

Create a dedicated unprivileged system user and installation directory:

~~~bash
sudo useradd -r -s /bin/false phonchain
sudo mkdir -p /opt/phonchain-node
sudo chown -R phonchain:phonchain /opt/phonchain-node
~~~

### 3) Install node software

Clone the repository:

~~~bash
git clone https://github.com/Phoncoin/phonchain-node.git
cd phonchain-node
~~~

Copy required files into the installation directory:

~~~bash
sudo cp app.py requirements.txt /opt/phonchain-node/
sudo cp config/example.env /opt/phonchain-node/.env
sudo chown -R phonchain:phonchain /opt/phonchain-node
~~~

Create a virtual environment and install Python dependencies:

~~~bash
sudo -u phonchain python3 -m venv /opt/phonchain-node/.venv
sudo -u phonchain /opt/phonchain-node/.venv/bin/pip install -r /opt/phonchain-node/requirements.txt
~~~

### 4) Nginx reverse proxy (gateway only)

Install the provided Nginx configuration:

~~~bash
sudo cp nginx/phonchain-node.conf /etc/nginx/sites-available/phonchain-node
sudo ln -s /etc/nginx/sites-available/phonchain-node /etc/nginx/sites-enabled/phonchain-node
sudo nginx -t && sudo systemctl reload nginx
~~~

ℹ️ TLS (HTTPS) should be configured separately (e.g. Certbot / Let’s Encrypt).

### 5) systemd service

Install and enable the systemd service:

~~~bash
sudo cp systemd/phonchain-node.service /etc/systemd/system/phonchain-node.service
sudo systemctl daemon-reload
sudo systemctl enable --now phonchain-node.service
~~~

Check service status:

~~~bash
sudo systemctl status phonchain-node.service --no-pager
~~~

---

## Core node installation (private)

For core nodes:

- Skip the Nginx step
- Do NOT open ports 80 / 443
- Keep API bound to `127.0.0.1:5000`
- Access only via local admin, VPN, or firewall whitelist (trusted gateway IPs)

---

## Final notes

- This repository provides reference implementation only
- Network identity is enforced by the canonical repository
- Operators may run nodes but cannot redefine Phonchain

For protocol rules and consensus:
👉 https://github.com/Phoncoin/phoncoin
