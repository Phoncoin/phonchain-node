# Phonchain — Genesis Cryptographic Proof (Offline Signature)

This document provides the public, verifiable proof that the Phonchain genesis statement
was signed offline, and that the genesis block hash declared here is the canonical origin.

---

## Network
- Chain name: Phonchain
- Ticker: PHC
- Consensus: Proof-of-Phone (PoP Secure v4.1)

## Genesis block canonical hash
c098fa5e985edd56634af262975b771f0dadc607494d6875cb725f1006611658

## Genesis timestamp (UTC)
2025-10-09 08:53:20

---

## Canonical genesis statement (SIGNED MESSAGE)

IMPORTANT:
The signed message uses Windows CRLF line endings (\r\n) and ends with a final CRLF.
Do not alter whitespace or line endings, or signature verification will fail.

(See `genesis.txt` in this repository.)

---

## SHA-256 of `genesis.txt` (CRLF version)

932053e47f24809864deaeb9b74ea52860e7065d040d0acacbd0730166d20e33

---

## Signature algorithm
Ed25519

---

## Creator public key (PEM)

-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAAM5fW18aGepMzZJ1hJCgIPmgOsfncNrohhKKqib/TXo=
-----END PUBLIC KEY-----

Public key (raw hex):
00ce5f5b5f1a19ea4ccd92758490a020f9a03ac7e770dae886128aaa26ff4d7a

---

## Signature over `genesis.txt`

Signature (raw bytes length): 64

Signature (base64):
duVPSgMDYShOfKtoBwnSjSnOJmYc9d+tY8wW3XT2DFG6gSTxnq2AghXjtCOR8q7Xr96K9ZYJy6NjsBFS3y9hBg==

Signature (hex):
76e54f4a030361284e7cab680709d28d29ce26661cf5dfad63cc16dd74f60c51ba8124f19ead808215e3b42391f2aed7afde8af59609cba363b01152df2f6106

---

## Declaration

- This genesis statement was signed offline on an air-gapped device.
- The private key has never been connected to the Internet and is permanently stored offline.
- After this signature, no founder, creator, or authority retains any privileged role over the protocol or the network.
