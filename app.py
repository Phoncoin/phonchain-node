# -*- coding: utf-8 -*-
from __future__ import annotations

import time
import json
import os
import sqlite3
import hashlib
import threading
from dataclasses import dataclass
from typing import List, Optional, Dict, Any, Tuple

from pathlib import Path
from flask import Flask, request, jsonify, render_template_string, redirect, url_for
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# -------------------------------------------------------------------
# GLOBAL CONFIG
# -------------------------------------------------------------------

# Data directory: keep runtime state out of the repo and avoid permission issues.
# - Default: <repo>/data (works for local dev).
# - In production: set PHONCHAIN_DATA_DIR=/var/lib/phonchain-node (recommended).
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("PHONCHAIN_DATA_DIR", str(BASE_DIR / "data")))
DATA_DIR.mkdir(parents=True, exist_ok=True)
# Database path (SQLite). If POAM_DB is relative, it is resolved inside DATA_DIR.
_poam_db = os.environ.get("POAM_DB", "poam_node.db")
DB_PATH = str((DATA_DIR / _poam_db) if not os.path.isabs(_poam_db) else Path(_poam_db))

CHAIN_NAME = "Phonchain"
TICKER = "PHC"
CONSENSUS_NAME = "Proof-of-Phone (PoP Secure v4.1)"
GENESIS_HASH = "c098fa5e985edd56634af262975b771f0dadc607494d6875cb725f1006611658"

# -------------------------------------------------------------------
# MONETARY POLICY (Bitcoin-like)
# -------------------------------------------------------------------

TOTAL_SUPPLY_CAP_PHC = 21_000_000
BLOCK_REWARD_PHC = int(os.environ.get("BLOCK_REWARD_PHC", "25"))
HALVING_INTERVAL = 420_000

TARGET_BLOCK_TIME = int(os.environ.get("TARGET_BLOCK_TIME", "300"))  # 5 minutes
GENESIS_TIMESTAMP = 1760000000  # 2025-10-09 08:53:20 UTC (FROZEN)
# Difficulty tuning
DIFFICULTY_WINDOW = int(os.environ.get("DIFFICULTY_WINDOW", "240"))
DIFFICULTY_CLAMP_MIN = int(os.environ.get("DIFFICULTY_MIN", "2"))
DIFFICULTY_CLAMP_MAX = int(os.environ.get("DIFFICULTY_MAX", "4"))  # node default
INITIAL_DIFFICULTY_ZEROS = int(os.environ.get("INITIAL_DIFFICULTY_ZEROS", "3"))

# Anti-freeze rescue mode (does not change block format; only prevents network stall)
DIFF_RESCUE_AFTER_SEC = int(os.environ.get("DIFF_RESCUE_AFTER_SEC", "1800"))
DIFF_RESCUE_STEP_SEC = int(os.environ.get("DIFF_RESCUE_STEP_SEC", "300"))

# Heartbeat rules
MAX_HEARTBEAT_AGE = int(os.environ.get("MAX_HEARTBEAT_AGE", str(60 * 60)))  # 1h

# Block aggregation behavior
MIN_BLOCK_HB = int(os.environ.get("MIN_BLOCK_HB", "1"))
BLOCK_THRESHOLD = int(os.environ.get("BLOCK_THRESHOLD", "30000"))  # node default

# Adaptive "force block" threshold (HB mempool) to keep block cadence stable even with many miners.
# This affects block production policy only (not block format / consensus rules).
ADAPTIVE_BLOCK_THRESHOLD = int(os.environ.get("ADAPTIVE_BLOCK_THRESHOLD", "1"))  # 1=on, 0=off
ADAPTIVE_BLOCK_THRESHOLD_MIN = int(os.environ.get("ADAPTIVE_BLOCK_THRESHOLD_MIN", "20000"))
ADAPTIVE_BLOCK_THRESHOLD_MAX = int(os.environ.get("ADAPTIVE_BLOCK_THRESHOLD_MAX", "2000000"))
ADAPTIVE_BLOCK_THRESHOLD_MINERS_REF = int(os.environ.get("ADAPTIVE_BLOCK_THRESHOLD_MINERS_REF", "1000"))  # 1000 miners -> MIN
MAX_BLOCK_HB = int(os.environ.get("MAX_BLOCK_HB", "30000"))  # node default

# TX aggregation
MIN_BLOCK_TX = int(os.environ.get("MIN_BLOCK_TX", "0"))         # 0 = blocs HB-only OK
TX_THRESHOLD = int(os.environ.get("TX_THRESHOLD", "200"))         # seuil indicatif (UI/metrics), ne force PAS la création de bloc
MAX_BLOCK_TX = int(os.environ.get("MAX_BLOCK_TX", "20000"))

# Heartbeat rate limiting
MIN_SECONDS_BETWEEN_HB_PER_PUBKEY = int(os.environ.get("HB_RATE_PUBKEY", "180"))  # FROZEN DEFAULT
MIN_SECONDS_BETWEEN_HB_PER_DEVICE = int(os.environ.get("HB_RATE_DEVICE", "180"))  # FROZEN DEFAULT

# -------------------------------------------------------------------
# CONSENSUS GUARDS (Post-genesis hardening)
# -------------------------------------------------------------------
# These checks prevent accidental fork by misconfigured .env values.
# They DO NOT change your current chain; they only refuse to start if mismatched.

if MIN_SECONDS_BETWEEN_HB_PER_PUBKEY != 180 or MIN_SECONDS_BETWEEN_HB_PER_DEVICE != 180:
    raise SystemExit(
        f"Consensus mismatch: HB_RATE must be 180s on all nodes "
        f"(pubkey={MIN_SECONDS_BETWEEN_HB_PER_PUBKEY}, device={MIN_SECONDS_BETWEEN_HB_PER_DEVICE})"
    )

# TX anti-spam (mempool admission only; does not change consensus / block format)
MAX_TXPOOL = int(os.environ.get("MAX_TXPOOL", "200000"))
MIN_SECONDS_BETWEEN_TX_PER_PUBKEY = int(os.environ.get("TX_RATE_PUBKEY", "1"))
MAX_PENDING_TX_PER_PUBKEY = int(os.environ.get("MAX_PENDING_TX_PER_PUBKEY", "200"))
MAX_TX_AGE = int(os.environ.get("MAX_TX_AGE", str(30 * 60)))  # 30 minutes

# Token scale (6 decimals)
SCALE_RAW_PER_PHC = 1_000_000
TOTAL_SUPPLY_CAP_RAW = TOTAL_SUPPLY_CAP_PHC * SCALE_RAW_PER_PHC
BLOCK_REWARD_RAW = BLOCK_REWARD_PHC * SCALE_RAW_PER_PHC

MIN_DEVICE_SCORE = int(os.environ.get("MIN_DEVICE_SCORE", "30"))

# Optional stricter binding (0/1)
STRICT_DEVICE_BINDING = int(os.environ.get("STRICT_DEVICE_BINDING", "0"))

# Explorer metrics options
ACTIVE_MINERS_WINDOW_SEC = int(os.environ.get("ACTIVE_MINERS_WINDOW_SEC", "600"))  # 10 minutes
METRICS_DEFAULT_N = int(os.environ.get("METRICS_DEFAULT_N", "120"))  # last N blocks


# -------------------------------------------------------------------
# L2 (soft) - instant acceptance, L1 finality
# -------------------------------------------------------------------
# We keep PoP mining + 5min target for L1 blocks (Bitcoin-like cadence).
# Transactions are accepted immediately into the mempool (L2) and become FINAL once included in an L1 block.
L2_ENABLED = int(os.environ.get("L2_ENABLED", "1"))


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fmt_utc(ts: int) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(int(ts)))


def short_hex(s: str, n: int = 16) -> str:
    s = s or ""
    return s if len(s) <= n else (s[:n] + "...")


# -------------------------------------------------------------------
# DATACLASSES
# -------------------------------------------------------------------

@dataclass
class Heartbeat:
    pubkey_hex: str
    timestamp: int
    nonce: str
    signature_hex: str
    device_fingerprint: str = ""
    device_info: Optional[Dict[str, Any]] = None
    latency_ms: int = -1


@dataclass
class Transaction:
    from_pubkey: str
    to_pubkey: str
    amount: int
    timestamp: int
    signature_hex: str
    txid: str = ""  # computed

    def compute_txid(self) -> str:
        payload = {
            "from": self.from_pubkey,
            "to": self.to_pubkey,
            "amount": int(self.amount),
            "timestamp": int(self.timestamp),
            "signature": self.signature_hex,
        }
        return sha256_hex(json.dumps(payload, sort_keys=True).encode())


@dataclass
class Block:
    index: int
    prev_hash: str
    timestamp: int
    heartbeats: List[Heartbeat]
    transactions: List[Transaction]
    block_hash: str = ""

    def compute_hash(self) -> str:
        """
        Consensus hash:
        - inclut heartbeats (champs v3/v4 stables) et transactions (on-chain).
        - latency_ms n'entre pas dans le hash (hors-consensus).
        """
        payload = {
            "index": self.index,
            "prev_hash": self.prev_hash,
            "timestamp": self.timestamp,
            "heartbeats": [
                {
                    "pubkey": h.pubkey_hex,
                    "timestamp": h.timestamp,
                    "nonce": h.nonce,
                    "signature": h.signature_hex,
                    "device_fingerprint": h.device_fingerprint,
                    "device_info": h.device_info or {},
                }
                for h in self.heartbeats
            ],
            "transactions": [
                {
                    "txid": tx.txid,
                    "from": tx.from_pubkey,
                    "to": tx.to_pubkey,
                    "amount": int(tx.amount),
                    "timestamp": int(tx.timestamp),
                    "signature": tx.signature_hex,
                }
                for tx in self.transactions
            ],
        }
        return sha256_hex(json.dumps(payload, sort_keys=True).encode())


# -------------------------------------------------------------------
# SQLITE PERSISTENCE
# -------------------------------------------------------------------

class PersistDB:
    def __init__(self, path: str = DB_PATH):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA foreign_keys=ON;")
        self._init()

    def _init(self) -> None:
        c = self.conn.cursor()

        c.execute(
            """
            CREATE TABLE IF NOT EXISTS blocks (
                idx INTEGER PRIMARY KEY,
                prev_hash TEXT,
                timestamp INTEGER,
                hash TEXT
            );
            """
        )

        c.execute(
            """
            CREATE TABLE IF NOT EXISTS heartbeats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                block_idx INTEGER,
                pubkey TEXT,
                timestamp INTEGER,
                nonce TEXT,
                signature TEXT,
                device_fingerprint TEXT,
                device_info TEXT,
                latency_ms INTEGER DEFAULT -1
            );
            """
        )

        # migration v4: add latency_ms on older db files
        try:
            c.execute("ALTER TABLE heartbeats ADD COLUMN latency_ms INTEGER DEFAULT -1;")
        except Exception:
            pass

        c.execute(
            """
            CREATE TABLE IF NOT EXISTS balances (
                pubkey TEXT PRIMARY KEY,
                balance_raw INTEGER
            );
            """
        )

        # legacy table (tu l’avais déjà). On la garde.
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                from_pubkey TEXT,
                to_pubkey TEXT,
                amount_raw INTEGER,
                timestamp INTEGER,
                signature TEXT
            );
            """
        )

        # ✅ ON-CHAIN TX table (bloc + txid)
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS txs (
                txid TEXT PRIMARY KEY,
                block_idx INTEGER,
                idx_in_block INTEGER,
                from_pubkey TEXT,
                to_pubkey TEXT,
                amount_raw INTEGER,
                timestamp INTEGER,
                signature TEXT
            );
            """
        )

        c.execute("CREATE INDEX IF NOT EXISTS idx_txs_block ON txs(block_idx);")
        c.execute("CREATE INDEX IF NOT EXISTS idx_txs_from_to ON txs(from_pubkey, to_pubkey);")

        # meta table (hors-consensus) pour metrics explorer
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS block_meta (
                idx INTEGER PRIMARY KEY,
                difficulty_zeros INTEGER,
                unique_miners INTEGER,
                hb_count INTEGER,
                tx_count INTEGER,
                created_ts INTEGER
            );
            """
        )

        # migration: add tx_count
        try:
            c.execute("ALTER TABLE block_meta ADD COLUMN tx_count INTEGER;")
        except Exception:
            pass

        c.execute("CREATE INDEX IF NOT EXISTS idx_heartbeats_block_idx ON heartbeats(block_idx);")
        c.execute("CREATE INDEX IF NOT EXISTS idx_heartbeats_pubkey ON heartbeats(pubkey);")

        self.conn.commit()

    def save_block(self, block: Block) -> None:
        c = self.conn.cursor()

        c.execute(
            "INSERT OR REPLACE INTO blocks(idx, prev_hash, timestamp, hash) VALUES (?, ?, ?, ?);",
            (block.index, block.prev_hash, block.timestamp, block.block_hash),
        )

        for hb in block.heartbeats:
            c.execute(
                """
                INSERT INTO heartbeats(
                    block_idx, pubkey, timestamp, nonce, signature,
                    device_fingerprint, device_info, latency_ms
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    block.index,
                    hb.pubkey_hex,
                    int(hb.timestamp),
                    hb.nonce,
                    hb.signature_hex,
                    hb.device_fingerprint,
                    json.dumps(hb.device_info or {}),
                    int(hb.latency_ms),
                ),
            )

        # ✅ on-chain txs
        for i, tx in enumerate(block.transactions):
            c.execute(
                """
                INSERT OR REPLACE INTO txs(
                    txid, block_idx, idx_in_block,
                    from_pubkey, to_pubkey, amount_raw, timestamp, signature
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    tx.txid,
                    int(block.index),
                    int(i),
                    tx.from_pubkey,
                    tx.to_pubkey,
                    int(tx.amount),
                    int(tx.timestamp),
                    tx.signature_hex,
                ),
            )

        self.conn.commit()

    def save_block_meta(
        self,
        idx: int,
        difficulty_zeros: int,
        unique_miners: int,
        hb_count: int,
        tx_count: int,
        created_ts: int,
    ) -> None:
        c = self.conn.cursor()
        c.execute(
            """
            INSERT OR REPLACE INTO block_meta(
                idx, difficulty_zeros, unique_miners, hb_count, tx_count, created_ts
            )
            VALUES (?, ?, ?, ?, ?, ?);
            """,
            (int(idx), int(difficulty_zeros), int(unique_miners), int(hb_count), int(tx_count), int(created_ts)),
        )
        self.conn.commit()

    def load_block_meta(self) -> Dict[int, Dict[str, int]]:
        c = self.conn.cursor()
        rows = c.execute("SELECT * FROM block_meta ORDER BY idx ASC;").fetchall()
        out: Dict[int, Dict[str, int]] = {}
        for r in rows:
            out[int(r["idx"])] = {
                "difficulty_zeros": int(r["difficulty_zeros"]) if r["difficulty_zeros"] is not None else -1,
                "unique_miners": int(r["unique_miners"]) if r["unique_miners"] is not None else 0,
                "hb_count": int(r["hb_count"]) if r["hb_count"] is not None else 0,
                "tx_count": int(r["tx_count"]) if "tx_count" in r.keys() and r["tx_count"] is not None else 0,
                "created_ts": int(r["created_ts"]) if r["created_ts"] is not None else 0,
            }
        return out

    def load_chain(self) -> List[Block]:
        c = self.conn.cursor()
        rows = c.execute("SELECT * FROM blocks ORDER BY idx ASC;").fetchall()

        chain: List[Block] = []
        for r in rows:
            idx = int(r["idx"])

            hbs = c.execute(
                "SELECT * FROM heartbeats WHERE block_idx = ? ORDER BY id ASC;",
                (idx,),
            ).fetchall()

            hb_list: List[Heartbeat] = []
            for h in hbs:
                info_raw = h["device_info"] or "{}"
                try:
                    info = json.loads(info_raw)
                except Exception:
                    info = {}
                lat = -1
                try:
                    if "latency_ms" in h.keys() and h["latency_ms"] is not None:
                        lat = int(h["latency_ms"])
                except Exception:
                    lat = -1

                hb_list.append(
                    Heartbeat(
                        pubkey_hex=h["pubkey"],
                        timestamp=int(h["timestamp"]),
                        nonce=h["nonce"],
                        signature_hex=h["signature"],
                        device_fingerprint=h["device_fingerprint"] or "",
                        device_info=info,
                        latency_ms=lat,
                    )
                )

            tx_rows = c.execute(
                "SELECT * FROM txs WHERE block_idx = ? ORDER BY idx_in_block ASC;",
                (idx,),
            ).fetchall()

            txs: List[Transaction] = []
            for t in tx_rows:
                txs.append(
                    Transaction(
                        from_pubkey=t["from_pubkey"],
                        to_pubkey=t["to_pubkey"],
                        amount=int(t["amount_raw"]),
                        timestamp=int(t["timestamp"]),
                        signature_hex=t["signature"],
                        txid=t["txid"],
                    )
                )

            chain.append(
                Block(
                    index=idx,
                    prev_hash=r["prev_hash"],
                    timestamp=int(r["timestamp"]),
                    heartbeats=hb_list,
                    transactions=txs,
                    block_hash=r["hash"],
                )
            )

        return chain

    def save_balance(self, pubkey: str, balance_raw: int) -> None:
        c = self.conn.cursor()
        c.execute(
            "INSERT OR REPLACE INTO balances(pubkey, balance_raw) VALUES (?, ?);",
            (pubkey, int(balance_raw)),
        )
        self.conn.commit()

    def load_balances(self) -> Dict[str, int]:
        c = self.conn.cursor()
        rows = c.execute("SELECT * FROM balances;").fetchall()
        return {r["pubkey"]: int(r["balance_raw"]) for r in rows}

    # legacy (garde)
    def save_transaction_legacy(self, tx: Transaction) -> None:
        c = self.conn.cursor()
        c.execute(
            """
            INSERT INTO transactions(from_pubkey, to_pubkey, amount_raw, timestamp, signature)
            VALUES (?, ?, ?, ?, ?);
            """,
            (tx.from_pubkey, tx.to_pubkey, int(tx.amount), int(tx.timestamp), tx.signature_hex),
        )
        self.conn.commit()

    def load_tx_by_txid(self, txid: str) -> Optional[Dict[str, Any]]:
        c = self.conn.cursor()
        r = c.execute("SELECT * FROM txs WHERE txid = ?;", (txid,)).fetchone()
        if not r:
            return None
        return {
            "txid": r["txid"],
            "block_idx": int(r["block_idx"]) if r["block_idx"] is not None else None,
            "idx_in_block": int(r["idx_in_block"]) if r["idx_in_block"] is not None else 0,
            "from_pubkey": r["from_pubkey"],
            "to_pubkey": r["to_pubkey"],
            "amount_raw": int(r["amount_raw"]),
            "timestamp": int(r["timestamp"]),
            "signature": r["signature"],
        }

    def load_recent_txs(self, limit: int = 50) -> List[Dict[str, Any]]:
        limit = max(1, min(int(limit), 500))
        c = self.conn.cursor()
        rows = c.execute(
            "SELECT * FROM txs ORDER BY block_idx DESC, idx_in_block DESC LIMIT ?;",
            (limit,),
        ).fetchall()
        out = []
        for r in rows:
            out.append(
                {
                    "txid": r["txid"],
                    "block_idx": int(r["block_idx"]) if r["block_idx"] is not None else None,
                    "from_pubkey": r["from_pubkey"],
                    "to_pubkey": r["to_pubkey"],
                    "amount_raw": int(r["amount_raw"]),
                    "timestamp": int(r["timestamp"]),
                }
            )
        return out

    # --- Explorer helpers (read-only) ---
    def txs_count(self) -> int:
        c = self.conn.cursor()
        r = c.execute("SELECT COUNT(1) AS n FROM txs;").fetchone()
        try:
            return int(r["n"]) if r and "n" in r.keys() else 0
        except Exception:
            return int(r[0]) if r else 0

    def load_txs_page(self, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """Paginated on-chain txs (newest first)."""
        limit = max(1, min(int(limit), 200))
        offset = max(0, int(offset))
        c = self.conn.cursor()
        rows = c.execute(
            "SELECT * FROM txs ORDER BY block_idx DESC, idx_in_block DESC LIMIT ? OFFSET ?;",
            (limit, offset),
        ).fetchall()
        out = []
        for r in rows:
            out.append(
                {
                    "txid": r["txid"],
                    "block_idx": int(r["block_idx"]) if r["block_idx"] is not None else None,
                    "idx_in_block": int(r["idx_in_block"]) if "idx_in_block" in r.keys() and r["idx_in_block"] is not None else 0,
                    "from_pubkey": r["from_pubkey"],
                    "to_pubkey": r["to_pubkey"],
                    "amount_raw": int(r["amount_raw"]),
                    "timestamp": int(r["timestamp"]),
                }
            )
        return out

    # ✅ recent txs filtered for one address (metamask-like)
    def load_recent_txs_for_address(self, address: str, limit: int = 50) -> List[Dict[str, Any]]:
        limit = max(1, min(int(limit), 500))
        c = self.conn.cursor()
        rows = c.execute(
            """
            SELECT * FROM txs
            WHERE from_pubkey = ? OR to_pubkey = ?
            ORDER BY block_idx DESC, idx_in_block DESC
            LIMIT ?;
            """,
            (address, address, limit),
        ).fetchall()
        out = []
        for r in rows:
            out.append(
                {
                    "txid": r["txid"],
                    "block_idx": int(r["block_idx"]) if r["block_idx"] is not None else None,
                    "from_pubkey": r["from_pubkey"],
                    "to_pubkey": r["to_pubkey"],
                    "amount_raw": int(r["amount_raw"]),
                    "timestamp": int(r["timestamp"]),
                }
            )
        return out

# -------------------------------------------------------------------
# NODE (PoP Secure v4.1)
# -------------------------------------------------------------------

class Node:
    def __init__(self, db: Optional[PersistDB] = None):
        self.db = db or PersistDB()
        self.lock = threading.RLock()

        self.chain: List[Block] = self.db.load_chain()

        if not self.chain:
            genesis = Block(
                index=0,
                prev_hash="0" * 64,
                timestamp=int(GENESIS_TIMESTAMP),
                heartbeats=[],
                transactions=[],
            )
            genesis.block_hash = genesis.compute_hash()
            self.chain = [genesis]
            self.db.save_block(genesis)
            self.db.save_block_meta(0, INITIAL_DIFFICULTY_ZEROS, 0, 0, 0, genesis.timestamp)

        # --- GENESIS IMMUTABILITY CHECK ---
        # Always verify genesis matches the frozen GENESIS_HASH.
        g = self.chain[0]
        try:
            calc = g.compute_hash()
        except Exception as e:
            raise SystemExit(f"Fatal: cannot compute genesis hash: {e}")

        if (g.block_hash or "").strip().lower() != calc:
            # Ensure stored hash is consistent with computed consensus hash
            g.block_hash = calc

        if g.block_hash.lower() != GENESIS_HASH.lower():
            raise SystemExit(
                "Fatal: genesis hash mismatch. This node would fork or join the wrong chain. "
                f"expected={GENESIS_HASH} got={g.block_hash}"
            )

        self.mempool: Dict[str, Heartbeat] = {}  # pubkey -> latest heartbeat (anti-spam, 1 HB per miner)
        self.txpool: List[Transaction] = []

        self.balances: Dict[str, int] = self.db.load_balances()

        self.clients_seen: Dict[str, int] = {}
        self.device_last_seen: Dict[str, int] = {}
        self.device_bindings: Dict[str, str] = {}

        # TX sender rate-limit tracking
        self.tx_last_seen: Dict[str, int] = {}

        self.total_issued_raw: int = sum(self.balances.values())
        self.difficulty_zeros: int = INITIAL_DIFFICULTY_ZEROS
        self.last_block_timestamp: int = self.chain[-1].timestamp

        self.block_meta: Dict[int, Dict[str, int]] = self.db.load_block_meta()

        self._stop_flag = False
        self._scheduler_thread = threading.Thread(target=self._block_scheduler_loop, daemon=True)
        self._scheduler_thread.start()

    def effective_difficulty_zeros(self, now: int) -> int:
        """Return required PoW zeros.

        Normal operation returns self.difficulty_zeros.
        If the chain is stalled for a long time (no blocks),
        lowers the effective difficulty progressively down to DIFFICULTY_CLAMP_MIN
        so the network cannot permanently freeze.
        """
        eff = int(self.difficulty_zeros)
        stall = max(0, int(now) - int(self.last_block_timestamp))
        if stall <= DIFF_RESCUE_AFTER_SEC:
            return eff

        steps = (stall - DIFF_RESCUE_AFTER_SEC) // max(1, DIFF_RESCUE_STEP_SEC)
        eff = eff - int(steps) - 1
        return max(DIFFICULTY_CLAMP_MIN, int(eff))


    def stop(self) -> None:
        self._stop_flag = True

    def _block_scheduler_loop(self) -> None:
        while not self._stop_flag:
            try:
                now = int(time.time())
                with self.lock:
                    due_time = (now - self.last_block_timestamp) >= TARGET_BLOCK_TIME

                    # Snapshot counts once (scalable)
                    hb_count = self.hb_mempool_count()
                    tx_count = len(self.txpool)

                    # Create blocks on the time cadence when there's something to include
                    due_hb = hb_count >= MIN_BLOCK_HB
                    due_tx = tx_count > 0

                    # HB threshold (adaptive) may also trigger a block
                    dyn_thr = self.dynamic_block_threshold()
                    force_hb = hb_count >= dyn_thr

                    # IMPORTANT: TX volume must NOT force blocks at global scale.
                    # TX_THRESHOLD remains a UI/metrics indicator only.
                    if (due_time and (due_hb or due_tx)) or force_hb:
                        self._create_block_locked(now, trigger="timer" if due_time else "threshold")
            except Exception as e:
                print("[SCHEDULER] error:", e)
            time.sleep(1)


    # ------------------ HB MEMPOOL (scalable) ------------------

    def hb_mempool_list(self) -> List[Heartbeat]:
        """Snapshot list of current HB mempool, ordered by timestamp (oldest first).
        Internally we store only the latest HB per pubkey to avoid mempool growth.
        """
        self._prune_hb_mempool_locked(int(time.time()))
        items = list(self.mempool.values())
        items.sort(key=lambda h: int(getattr(h, "timestamp", 0)))
        return items

    def hb_mempool_count(self) -> int:
        self._prune_hb_mempool_locked(int(time.time()))
        return len(self.mempool)

    def _prune_hb_mempool_locked(self, now: Optional[int] = None) -> int:
        """Remove stale HB entries from mempool (keeps only recent active miners).
        Returns the number of removed entries.
        """
        now = int(now or time.time())
        cutoff = now - int(MAX_HEARTBEAT_AGE)
        removed = 0
        for pk, hb in list(self.mempool.items()):
            try:
                ts = int(getattr(hb, "timestamp", 0))
            except Exception:
                ts = 0
            if ts < cutoff:
                self.mempool.pop(pk, None)
                removed += 1
        return removed

    def holders_count(self) -> int:
        return sum(1 for _pk, raw in self.balances.items() if int(raw) > 0)

    def active_miners(self, window_sec: int = ACTIVE_MINERS_WINDOW_SEC) -> int:
        cutoff = int(time.time()) - int(window_sec)
        miners = set()

        for hb in self.hb_mempool_list():
            if hb.timestamp >= cutoff:
                miners.add(hb.pubkey_hex)

        for b in reversed(self.chain):
            if b.timestamp < cutoff:
                break
            for hb in b.heartbeats:
                if hb.timestamp >= cutoff:
                    miners.add(hb.pubkey_hex)

        return len(miners)

    def dynamic_block_threshold(self) -> int:
        """HB mempool threshold that triggers an early block (before timer).
        Scales with active miners (last 10 minutes) to avoid too-frequent blocks when miner count grows,
        keeping issuance/halving cadence stable around TARGET_BLOCK_TIME.
        """
        if ADAPTIVE_BLOCK_THRESHOLD != 1:
            return int(BLOCK_THRESHOLD)

        miners = int(self.active_miners(ACTIVE_MINERS_WINDOW_SEC))
        ref = max(1, int(ADAPTIVE_BLOCK_THRESHOLD_MINERS_REF))
        base = int(ADAPTIVE_BLOCK_THRESHOLD_MIN)

        # Scale linearly: <=ref miners => base, 10x miners => 10x threshold, etc.
        mult = max(1, (miners + ref - 1) // ref)  # ceil(miners/ref), min 1
        thr = base * int(mult)

        thr = max(int(ADAPTIVE_BLOCK_THRESHOLD_MIN), min(int(thr), int(ADAPTIVE_BLOCK_THRESHOLD_MAX)))
        return int(thr)


    def block_reward_raw(self, height: int) -> int:
        if height <= 0:
            return 0

        halvings = height // HALVING_INTERVAL
        reward = BLOCK_REWARD_RAW >> halvings

        if self.total_issued_raw + reward > TOTAL_SUPPLY_CAP_RAW:
            reward = max(TOTAL_SUPPLY_CAP_RAW - self.total_issued_raw, 0)

        return max(int(reward), 0)


        # ------------------ DEVICE CHECK (PoP Secure v4.1 FINAL) ------------------

    def eval_device_info(self, hb: Heartbeat) -> Dict[str, Any]:
        info = hb.device_info or {}

        is_emulator = bool(info.get("is_emulator", False))
        is_rooted = bool(info.get("is_rooted", False))

        # ✅ score OU trust_score (whitepaper)
        score = int(info.get("score", info.get("trust_score", 50)))
        score = max(0, min(score, 100))

        # ✅ Play Integrity — bool legacy
        pi_basic = bool(info.get("play_integrity_basic", False))
        pi_device = bool(info.get("play_integrity_device", False))

        # ✅ Play Integrity — string whitepaper
        pi_str = str(info.get("play_integrity", "unknown")).lower()
        if pi_str in ("ok", "device", "strong"):
            pi_device = True
        elif pi_str in ("basic", "cts"):
            pi_basic = True
        elif pi_str in ("failed", "error"):
            pi_basic = False
            pi_device = False

        google_play_certified = bool(info.get("google_play_certified", False))

        # ❌ Emulator = rejet immédiat
        if is_emulator:
            return {"ok": False, "reason": "emulator", "score": 0}

        # ❌ Root + score nul
        if is_rooted and score <= 0:
            return {"ok": False, "reason": "rooted_low_score", "score": 0}

        # 🎖️ Bonus integrity
        if pi_device:
            score = max(score, 80)
        elif pi_basic:
            score = max(score, 60)

        # ⚠️ Root sans integrity → plafonné
        if is_rooted and not (pi_basic or pi_device):
            score = min(score, 30)

        latency_ms = hb.latency_ms
        latency_note = "unknown"
        if latency_ms >= 0:
            if latency_ms < 10:
                latency_note = "very_fast"
            elif latency_ms < 150:
                latency_note = "normal"
            elif latency_ms < 800:
                latency_note = "slow"
            else:
                latency_note = "very_slow"

        if score < MIN_DEVICE_SCORE:
            return {
                "ok": False,
                "reason": "low_score",
                "score": score,
                "play_integrity": "ok" if pi_device else ("basic" if pi_basic else "unknown"),
                "latency_ms": latency_ms,
                "latency_note": latency_note,
            }

        return {
            "ok": True,
            "reason": "ok",
            "score": score,
            "google_play_certified": google_play_certified,
            "play_integrity": "ok" if pi_device else ("basic" if pi_basic else "unknown"),
            "latency_ms": latency_ms,
            "latency_note": latency_note,
        }


    # ------------------ HEARTBEAT ------------------

    def verify_heartbeat(self, hb: Heartbeat) -> Tuple[bool, str, Dict[str, Any]]:
        now = int(time.time())

        if not hb.device_fingerprint:
            return False, "missing_fingerprint", {}

        if abs(now - hb.timestamp) > MAX_HEARTBEAT_AGE:
            return False, "heartbeat_too_old", {}

        bound_pk = self.device_bindings.get(hb.device_fingerprint)
        if bound_pk is not None and bound_pk != hb.pubkey_hex and STRICT_DEVICE_BINDING == 1:
            return False, "fingerprint_bound_to_other_pubkey", {"bound": bound_pk}

        # signature
        try:
            pub_bytes = bytes.fromhex(hb.pubkey_hex)
            pk = Ed25519PublicKey.from_public_bytes(pub_bytes)
            payload_str = hb.pubkey_hex + str(hb.timestamp) + hb.nonce + hb.device_fingerprint
            pk.verify(bytes.fromhex(hb.signature_hex), payload_str.encode())
        except Exception:
            return False, "bad_signature", {}

        # rate limit (pubkey)
        last_ts_addr = self.clients_seen.get(hb.pubkey_hex)
        if last_ts_addr is not None:
            if hb.timestamp <= last_ts_addr:
                return False, "replay_or_non_increasing_timestamp", {}
            if hb.timestamp - last_ts_addr < MIN_SECONDS_BETWEEN_HB_PER_PUBKEY:
                return False, "rate_limited_pubkey", {"min_seconds": MIN_SECONDS_BETWEEN_HB_PER_PUBKEY}
        self.clients_seen[hb.pubkey_hex] = hb.timestamp

        # rate limit (device)
        last_ts_dev = self.device_last_seen.get(hb.device_fingerprint)
        if last_ts_dev is not None and (hb.timestamp - last_ts_dev) < MIN_SECONDS_BETWEEN_HB_PER_DEVICE:
            return False, "rate_limited_device", {"min_seconds": MIN_SECONDS_BETWEEN_HB_PER_DEVICE}
        self.device_last_seen[hb.device_fingerprint] = hb.timestamp

        # bind
        if bound_pk is None:
            self.device_bindings[hb.device_fingerprint] = hb.pubkey_hex
        elif bound_pk != hb.pubkey_hex:
            print("[SECURITY] fingerprint multi-address:", hb.device_fingerprint[:16], "old=", bound_pk[:16], "new=", hb.pubkey_hex[:16])

        # PoW check (CONSENSUS)
        hb_hash = sha256_hex((hb.pubkey_hex + str(hb.timestamp) + hb.nonce + hb.device_fingerprint).encode())
        eff = self.effective_difficulty_zeros(now)
        if not hb_hash.startswith("0" * eff):
            return False, "pow_invalid", {"difficulty_zeros": self.difficulty_zeros, "effective_difficulty_zeros": eff}

        dev_res = self.eval_device_info(hb)
        if not dev_res.get("ok", False):
            return False, f"device_{dev_res.get('reason','rejected')}", dev_res

        return True, "ok", dev_res

    def submit_heartbeat(self, hb: Heartbeat) -> Tuple[bool, str, Dict[str, Any]]:
        with self.lock:
            ok, reason, meta = self.verify_heartbeat(hb)
            if not ok:
                return False, reason, meta

            self._prune_hb_mempool_locked(int(time.time()))
            self.mempool[hb.pubkey_hex] = hb  # replace latest (1 HB per miner)
            self.balances.setdefault(hb.pubkey_hex, 0)
            self.db.save_balance(hb.pubkey_hex, self.balances[hb.pubkey_hex])

            return True, "accepted", meta

    # ------------------ TRANSACTIONS ------------------

    def pending_outgoing_raw(self, from_pubkey: str) -> int:
        s = 0
        for tx in self.txpool:
            if tx.from_pubkey == from_pubkey:
                s += int(tx.amount)
        return s

    def verify_transaction(self, tx: Transaction) -> Tuple[bool, str]:
        now = int(time.time())

        # TX age guard (prevents very old replays flooding mempool)
        if abs(now - int(tx.timestamp)) > MAX_TX_AGE:
            return False, "tx_too_old"

        # Sender rate limit (applied before heavy checks)
        # Use server time to prevent bypass via forged client timestamps.
        last = self.tx_last_seen.get(tx.from_pubkey)
        if last is not None and (now - int(last)) < MIN_SECONDS_BETWEEN_TX_PER_PUBKEY:
            return False, "rate_limited_tx"

        if tx.amount <= 0:
            return False, "amount_invalid"

        if tx.from_pubkey == tx.to_pubkey:
            return False, "self_transfer_not_allowed"

        balance_raw = self.balances.get(tx.from_pubkey, 0)
        pending = self.pending_outgoing_raw(tx.from_pubkey)
        available = balance_raw - pending
        if available < tx.amount:
            return False, "insufficient_funds"

        try:
            pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(tx.from_pubkey))
            payload = (tx.from_pubkey + tx.to_pubkey + str(int(tx.amount)) + str(int(tx.timestamp))).encode()
            pk.verify(bytes.fromhex(tx.signature_hex), payload)
        except Exception:
            return False, "bad_signature"

        if not tx.txid:
            tx.txid = tx.compute_txid()

        return True, "ok"

    def submit_transaction(self, tx: Transaction) -> Tuple[bool, str, Dict[str, Any]]:
        with self.lock:
            ok, reason = self.verify_transaction(tx)
            if not ok:
                return False, reason, {}

            if any(t.txid == tx.txid for t in self.txpool):
                return False, "tx_already_in_mempool", {"txid": tx.txid}

            # TX pool caps (anti-spam)
            if len(self.txpool) >= MAX_TXPOOL:
                return False, "txpool_full", {"max": MAX_TXPOOL}

            pending_sender = sum(1 for t in self.txpool if t.from_pubkey == tx.from_pubkey)
            if pending_sender >= MAX_PENDING_TX_PER_PUBKEY:
                return False, "too_many_pending_for_sender", {"max": MAX_PENDING_TX_PER_PUBKEY}

            self.txpool.append(tx)
            # Record sender timestamp after acceptance
            self.tx_last_seen[tx.from_pubkey] = int(time.time())

            try:
                self.db.save_transaction_legacy(tx)
            except Exception:
                pass

            return True, "accepted", {"txid": tx.txid}

    def _apply_tx_locked(self, tx: Transaction) -> None:
        self.balances.setdefault(tx.from_pubkey, 0)
        self.balances.setdefault(tx.to_pubkey, 0)

        self.balances[tx.from_pubkey] -= int(tx.amount)
        self.balances[tx.to_pubkey] += int(tx.amount)

        self.db.save_balance(tx.from_pubkey, self.balances[tx.from_pubkey])
        self.db.save_balance(tx.to_pubkey, self.balances[tx.to_pubkey])

    # ------------------ BLOCK CREATION ------------------

    def _create_block_locked(self, now: int, trigger: str) -> None:
        prev = self.chain[-1]

        hb_items = self.hb_mempool_list()

        take_hb = hb_items[:MAX_BLOCK_HB]
        rest_hb = hb_items[MAX_BLOCK_HB:]

        take_tx = self.txpool[:MAX_BLOCK_TX]
        rest_tx = self.txpool[MAX_BLOCK_TX:]

        snap_difficulty = int(self.difficulty_zeros)
        snap_unique = len({hb.pubkey_hex for hb in take_hb})
        snap_hb = len(take_hb)
        snap_tx = len(take_tx)

        blk = Block(
            index=len(self.chain),
            prev_hash=prev.block_hash,
            timestamp=now,
            heartbeats=take_hb,
            transactions=take_tx,
        )

        for tx in blk.transactions:
            if not tx.txid:
                tx.txid = tx.compute_txid()

        # --- IMPORTANT ---
        # Pendant l'inclusion en bloc, on ne doit PAS vérifier une TX
        # contre un txpool qui contient déjà les TX du bloc (sinon double-compte du pending).
        # On bascule temporairement le txpool sur rest_tx (mempool restant).
        self.txpool = rest_tx

        # applique tx (si verify fail -> drop du bloc)
        applied = []
        for tx in blk.transactions:
            ok, reason = self.verify_transaction(tx)
            if not ok:
                print(f"[TX] dropped_in_block txid={getattr(tx,'txid',None)} reason={reason}")
                continue
            self._apply_tx_locked(tx)
            applied.append(tx)

        blk.transactions = applied

        blk.block_hash = blk.compute_hash()

        self.chain.append(blk)
        self.db.save_block(blk)

        self.db.save_block_meta(blk.index, snap_difficulty, snap_unique, snap_hb, len(blk.transactions), now)
        self.block_meta[blk.index] = {
            "difficulty_zeros": snap_difficulty,
            "unique_miners": snap_unique,
            "hb_count": snap_hb,
            "tx_count": len(blk.transactions),
            "created_ts": now,
        }

        unique_clients = list({hb.pubkey_hex for hb in blk.heartbeats})
        reward_raw = self.block_reward_raw(blk.index)

        if unique_clients and reward_raw > 0:
            per_raw = reward_raw // len(unique_clients)
            for pk in unique_clients:
                self.balances.setdefault(pk, 0)
                self.balances[pk] += per_raw
                self.db.save_balance(pk, self.balances[pk])
            self.total_issued_raw += reward_raw

        # Remove included heartbeats from HB mempool (1 HB per miner)
        for hb in take_hb:
            self.mempool.pop(hb.pubkey_hex, None)
        self.txpool = rest_tx

        self.last_block_timestamp = now
        self.adjust_difficulty_locked()

        print(
            f"[BLOCK] mined height={blk.index} hb={len(blk.heartbeats)} tx={len(blk.transactions)} "
            f"trigger={trigger} reward_raw={reward_raw} diff={self.difficulty_zeros}"
        )

    def adjust_difficulty_locked(self) -> None:
        height = len(self.chain) - 1
        if height < 2:
            return

        w = min(DIFFICULTY_WINDOW, height)
        start = max(1, height - w + 1)
        blocks = self.chain[start: height + 1]
        if len(blocks) < 2:
            return

        span = blocks[-1].timestamp - blocks[0].timestamp
        avg_block_time = span / max(len(blocks) - 1, 1)

        if avg_block_time < TARGET_BLOCK_TIME * 0.85:
            self.difficulty_zeros = min(self.difficulty_zeros + 1, DIFFICULTY_CLAMP_MAX)
        elif avg_block_time > TARGET_BLOCK_TIME * 1.15:
            self.difficulty_zeros = max(self.difficulty_zeros - 1, DIFFICULTY_CLAMP_MIN)

        if height % 25 == 0:
            print(f"[DIFF] height={height} avg_block_time={avg_block_time:.1f}s -> difficulty_zeros={self.difficulty_zeros}")

    def dump_chain(self) -> List[Dict[str, Any]]:
        return [
            {
                "index": b.index,
                "prev_hash": b.prev_hash,
                "hash": b.block_hash,
                "timestamp": b.timestamp,
                "hb": len(b.heartbeats),
                "tx": len(b.transactions),
            }
            for b in self.chain
        ]


# -------------------------------------------------------------------
# FLASK API
# -------------------------------------------------------------------

app = Flask(__name__)
node = Node()


@app.route("/submit_proof", methods=["POST"])
def submit_proof():
    j = request.get_json(silent=True) or {}
    try:
        hbj = j.get("heartbeat")
        if not isinstance(hbj, dict):
            raise ValueError("heartbeat must be an object")

        device_fingerprint = (hbj.get("device_fingerprint") or hbj.get("fingerprint_hash") or "").strip()

        device_info_legacy = hbj.get("device_info", {}) or {}
        device_info_v4 = hbj.get("device_info_v4", {}) or {}
        merged_info: Dict[str, Any] = {}
        merged_info.update(device_info_legacy)
        merged_info.update(device_info_v4)

        latency_ms = -1
        if "latency_ms" in hbj:
            try:
                latency_ms = int(hbj.get("latency_ms", -1))
            except Exception:
                latency_ms = -1
        if latency_ms < 0:
            try:
                if isinstance(merged_info, dict) and "latency_ms" in merged_info:
                    latency_ms = int(merged_info.get("latency_ms", -1))
            except Exception:
                latency_ms = -1

        hb = Heartbeat(
            pubkey_hex=str(hbj["pubkey"]),
            timestamp=int(hbj["timestamp"]),
            nonce=str(hbj["nonce"]),
            signature_hex=str(hbj["signature"]),
            device_fingerprint=device_fingerprint,
            device_info=merged_info,
            latency_ms=latency_ms,
        )
    except Exception as e:
        return jsonify({"ok": False, "reason": "bad_request", "error": str(e)}), 400

    ok, reason, meta = node.submit_heartbeat(hb)
    return jsonify({"ok": ok, "reason": reason, "meta": meta})


# ✅ MetaMask-like state for one address (total / pending / available + pending txs + confirmed txs)
@app.route("/address/<pubkey>/state")
def address_state(pubkey: str):
    pubkey = (pubkey or "").strip()
    with node.lock:
        balance_raw = int(node.balances.get(pubkey, 0))
        pending_raw = int(node.pending_outgoing_raw(pubkey))
        available_raw = balance_raw - pending_raw
        if available_raw < 0:
            available_raw = 0

        pending_txs = []
        for tx in node.txpool:
            if tx.from_pubkey == pubkey or tx.to_pubkey == pubkey:
                pending_txs.append(
                    {
                        "txid": tx.txid,
                        "from_pubkey": tx.from_pubkey,
                        "to_pubkey": tx.to_pubkey,
                        "amount_raw": int(tx.amount),
                        "timestamp": int(tx.timestamp),
                        "status": "pending",
                    }
                )

    confirmed = node.db.load_recent_txs_for_address(pubkey, limit=80)
    for t in confirmed:
        t["status"] = "confirmed"

    return jsonify(
        {
            "ok": True,
            "address": pubkey,
            "balance": {"raw": balance_raw, "phc": balance_raw / float(SCALE_RAW_PER_PHC)},
            "pending_outgoing": {"raw": pending_raw, "phc": pending_raw / float(SCALE_RAW_PER_PHC)},
            "available": {"raw": available_raw, "phc": available_raw / float(SCALE_RAW_PER_PHC)},
            "pending_txs": pending_txs[-80:],
            "recent_txs": confirmed,
        }
    )


@app.route("/address/<pubkey>/transactions")
def address_transactions(pubkey: str):
    """Wallet-grade TX history for one address.
    - pending: from mempool (L2)
    - confirmed: from DB (L1)
    """
    pubkey = (pubkey or "").strip()

    try:
        limit = int(request.args.get("limit", "80"))
    except Exception:
        limit = 80
    limit = max(1, min(limit, 200))

    with node.lock:
        pending = []
        for tx in node.txpool:
            if tx.from_pubkey == pubkey or tx.to_pubkey == pubkey:
                pending.append(
                    {
                        "txid": tx.txid,
                        "from_pubkey": tx.from_pubkey,
                        "to_pubkey": tx.to_pubkey,
                        "amount": {"raw": int(tx.amount), "phc": int(tx.amount) / float(SCALE_RAW_PER_PHC)},
                        "timestamp": int(tx.timestamp),
                        "status": "pending",
                        "layer": "L2",
                    }
                )

    confirmed = node.db.load_recent_txs_for_address(pubkey, limit=limit)
    for t in confirmed:
        t["amount"] = {"raw": int(t["amount_raw"]), "phc": int(t["amount_raw"]) / float(SCALE_RAW_PER_PHC)}
        t["status"] = "confirmed"
        t["layer"] = "L1"
        # clean legacy keys
        t.pop("amount_raw", None)

    return jsonify(
        {
            "ok": True,
            "address": pubkey,
            "pending": pending[-limit:],
            "confirmed": confirmed,
        }
    )


@app.route("/transfer", methods=["POST"])
def transfer():
    j = request.get_json(silent=True) or {}
    try:
        from_pk = j["from_pubkey"]
        to_pk = j["to_pubkey"]
        amount_raw = int(j["amount"])
        ts = int(j["timestamp"])
        sig = j["signature"]
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400

    tx = Transaction(from_pubkey=from_pk, to_pubkey=to_pk, amount=amount_raw, timestamp=ts, signature_hex=sig)
    tx.txid = tx.compute_txid()

    ok, reason, meta = node.submit_transaction(tx)

    # ✅ rétrocompatible + wallet-friendly (txid + status)
    return jsonify(
        {
            "ok": ok,
            "reason": reason,
            "meta": meta,
            "txid": tx.txid,
            "status": "pending" if ok else "rejected",
            "layer": "L2" if ok else "none",  # L2=mempool, L1=block
        }
    )

# ✅ Internal ingest (Core only) — allows gateways (B/C) to submit TX to Core A
@app.route("/internal/tx_ingest", methods=["POST"])
def internal_tx_ingest():
    # Protected by firewall (UFW: only B/C can reach A:5000)
    # Optional shared secret (recommended)
    key = request.headers.get("X-Internal-Key", "")
    expected = os.environ.get("INTERNAL_TX_KEY", "")
    if expected and key != expected:
        return jsonify({"ok": False, "reason": "forbidden"}), 403

    # Reuse the same behavior as /transfer
    return transfer()

@app.route("/tx/<txid>")
def tx_lookup(txid: str):
    r = node.db.load_tx_by_txid(txid.strip().lower())
    if not r:
        return jsonify({"ok": False, "reason": "not_found"}), 404
    return jsonify({"ok": True, "tx": r})




# ✅ L2/L1 status for a txid (wallet + explorer)
@app.route("/tx_status/<txid>")
def tx_status(txid: str):
    txid = (txid or "").strip().lower()
    if not txid:
        return jsonify({"ok": False, "reason": "bad_request"}), 400

    confirmed = node.db.load_tx_by_txid(txid)
    if confirmed:
        return jsonify(
            {
                "ok": True,
                "txid": txid,
                "status": "confirmed",
                "layer": "L1",
                "block_idx": confirmed.get("block_idx"),
                "idx_in_block": confirmed.get("idx_in_block"),
                "tx": confirmed,
            }
        )

    with node.lock:
        for i, t in enumerate(node.txpool):
            if (t.txid or "").lower() == txid:
                return jsonify(
                    {
                        "ok": True,
                        "txid": txid,
                        "status": "pending",
                        "layer": "L2",
                        "position": i,
                        "mempool_tx": len(node.txpool),
                        "tx": {
                            "txid": t.txid,
                            "from_pubkey": t.from_pubkey,
                            "to_pubkey": t.to_pubkey,
                            "amount_raw": int(t.amount),
                            "timestamp": int(t.timestamp),
                        },
                    }
                )

    return jsonify({"ok": False, "txid": txid, "status": "not_found"}), 404


# ✅ L2 aliases (same payloads; finality when included in L1 block)
@app.route("/l2/transfer", methods=["POST"])
def l2_transfer():
    if L2_ENABLED != 1:
        return jsonify({"ok": False, "reason": "l2_disabled"}), 403
    return transfer()


@app.route("/l2/tx/<txid>")
def l2_tx_lookup(txid: str):
    return tx_status(txid)

@app.route("/mempool")
def mempool():
    with node.lock:
        return jsonify(
            {
                "ok": True,
                "hb_mempool": len(node.mempool),
                "tx_mempool": len(node.txpool),
                "last_txids": [t.txid for t in node.txpool[-20:]],
                "last_hb_pubkeys": [hb.pubkey_hex[:16] for hb in node.hb_mempool_list()[-20:]],
            }
        )


@app.route("/chain")
def chain():
    return jsonify({"chain": node.dump_chain()})


@app.route("/balances")
def balances():
    out = {}
    for addr, raw in node.balances.items():
        phc = raw / float(SCALE_RAW_PER_PHC)
        out[addr] = {"phc": phc, "raw": raw}
    return jsonify({"balances": out})


@app.route("/balance/<pubkey>")
def balance(pubkey: str):
    raw = node.balances.get(pubkey, 0)
    phc = raw / float(SCALE_RAW_PER_PHC)
    return jsonify({"address": pubkey, "phc": phc, "raw": raw, "balance": {"phc": phc, "raw": raw}})


@app.route("/metrics")
def metrics():
    try:
        n = int(request.args.get("n", str(METRICS_DEFAULT_N)))
    except Exception:
        n = METRICS_DEFAULT_N

    n = max(10, min(n, 2000))
    height = len(node.chain) - 1
    start = max(0, height - n + 1)

    series = []
    for idx in range(start, height + 1):
        b = node.chain[idx]
        meta = node.block_meta.get(idx, {})
        series.append(
            {
                "height": idx,
                "timestamp": int(b.timestamp),
                "difficulty_zeros": int(meta.get("difficulty_zeros", node.difficulty_zeros)),
                "unique_miners": int(meta.get("unique_miners", len({hb.pubkey_hex for hb in b.heartbeats}))),
                "hb": int(meta.get("hb_count", len(b.heartbeats))),
                "tx": int(meta.get("tx_count", len(b.transactions))),
            }
        )

    return jsonify(
        {
            "ok": True,
            "chain_name": CHAIN_NAME,
            "ticker": TICKER,
            "height": height,
            "window": n,
            "series": series,
        }
    )


@app.route("/network_info")
def network_info():
    height = len(node.chain) - 1
    total_phc = node.total_issued_raw / float(SCALE_RAW_PER_PHC)
    total_cap_phc = TOTAL_SUPPLY_CAP_RAW / float(SCALE_RAW_PER_PHC)

    holders = node.holders_count()
    active_miners_10m = node.active_miners(ACTIVE_MINERS_WINDOW_SEC)

    with node.lock:
        txpool_n = len(node.txpool)
        hbpool_n = len(node.mempool)

    return jsonify(
        {
            "chain_name": CHAIN_NAME,
            "ticker": TICKER,
            "consensus": CONSENSUS_NAME,
            "genesis_hash": GENESIS_HASH,
            "height": height,
            "total_issued": {"phc": total_phc, "raw": node.total_issued_raw},
            "total_supply_cap": {"phc": total_cap_phc, "raw": TOTAL_SUPPLY_CAP_RAW},
            "difficulty_zeros": node.difficulty_zeros,
            "effective_difficulty_zeros": node.effective_difficulty_zeros(int(time.time())),
            "min_block_hb": MIN_BLOCK_HB,
            "block_threshold": BLOCK_THRESHOLD,
            "block_threshold_effective": node.dynamic_block_threshold(),
            "adaptive_block_threshold": ADAPTIVE_BLOCK_THRESHOLD,
            "max_block_hb": MAX_BLOCK_HB,
            "min_block_tx": MIN_BLOCK_TX,
            "tx_threshold": TX_THRESHOLD,
            "max_block_tx": MAX_BLOCK_TX,
            "target_block_time": TARGET_BLOCK_TIME,
            "integrity_mode": "pop-secure-v4.1",
            "min_device_score": MIN_DEVICE_SCORE,
            "hb_rate_pubkey_sec": MIN_SECONDS_BETWEEN_HB_PER_PUBKEY,
            "hb_rate_device_sec": MIN_SECONDS_BETWEEN_HB_PER_DEVICE,
            "holders": holders,
            "active_miners_10m": active_miners_10m,
            "mempool_hb": hbpool_n,
            "mempool_tx": txpool_n,
        }
    )


@app.route("/debug/state")
def debug_state():
    height = len(node.chain) - 1
    with node.lock:
        return jsonify(
            {
                "height": height,
                "mempool_size": len(node.mempool),
                "txpool_size": len(node.txpool),
                "difficulty_zeros": node.difficulty_zeros,
            "effective_difficulty_zeros": node.effective_difficulty_zeros(int(time.time())),
                "balances_count": len(node.balances),
                "total_issued_raw": node.total_issued_raw,
                "last_block_ts": node.last_block_timestamp,
                "last_mempool_pubkeys": [hb.pubkey_hex[:16] for hb in node.hb_mempool_list()[-10:]],
                "last_txids": [t.txid[:16] for t in node.txpool[-10:]],
            }
        )



@app.route("/healthz")
def healthz():
    """Lightweight health check for uptime monitors and load balancers."""
    return jsonify({"ok": True, "chain": CHAIN_NAME, "height": len(node.chain) - 1, "ts": int(time.time())})

@app.route("/")
def index():
    height = len(node.chain) - 1
    total_phc = node.total_issued_raw / float(SCALE_RAW_PER_PHC)
    return jsonify(
        {
            "ok": True,
            "message": "Phonchain node online (PoP Secure v4.1)",
            "ticker": TICKER,
            "height": height,
            "total_issued": {"phc": total_phc, "raw": node.total_issued_raw},
        }
    )


# -------------------------------------------------------------------
# EXPLORER
# -------------------------------------------------------------------

EXPLORER_BASE_TEMPLATE = """<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>PHONCOIN - EXPLORER</title>
  <style>
    body { background-color: #02040a; color: #f5f5f5; font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 0; padding: 0; }
    header { padding: 16px 32px; border-bottom: 1px solid #1b1f2a; display: flex; justify-content: space-between; align-items: center; background: radial-gradient(circle at top left, rgba(0,255,170,0.16), transparent 55%); }
    .header-left { display: flex; align-items: center; gap: 12px; }
    .logo { width: 38px; height: 38px; border-radius: 10px; box-shadow: 0 0 18px rgba(0, 255, 170, 0.6), 0 0 2px rgba(0, 0, 0, 0.8); background: #020617; }
    .title { font-weight: 700; letter-spacing: 0.14em; font-size: 15px; text-transform: uppercase; color: #00ffaa; text-shadow: 0 0 8px rgba(0, 255, 170, 0.5); }
    .subtitle { font-size: 12px; color: #9ca3af; margin-top: 2px; }
    header .stats { font-size: 12px; color: #e5e7eb; text-align: right; }
    .container { max-width: 1200px; margin: 32px auto; padding: 0 16px 64px; }
    .card { background: radial-gradient(circle at top left, rgba(0,255,170,0.06), transparent 60%), #050814; border-radius: 12px; border: 1px solid #0f172a; padding: 20px 24px; margin-bottom: 24px; box-shadow: 0 0 18px rgba(0,255,170,0.12), 0 18px 35px rgba(0,0,0,0.7); }
    .card h2 { font-size: 16px; margin: 0 0 8px; color: #e5e7eb; }
    .muted { color: #9ca3af; font-size: 12px; }
    table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 13px; }
    th, td { padding: 8px 6px; text-align: left; border-bottom: 1px solid #111827; vertical-align: top; }
    th { font-weight: 500; color: #9ca3af; font-size: 12px; }
    tr:hover td { background-color: #0b1020; }
    a { color: #00ffaa; text-decoration: none; transition: all 0.12s ease-out; }
    a:hover { text-shadow: 0 0 6px rgba(0,255,170,0.8); color: #a7ffdf; }
    .search-row { margin-top: 8px; display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
    .search-row input[type=text] { width: 520px; max-width: 100%; padding: 8px 10px; border-radius: 8px; border: 1px solid #111827; background: #020617; color: #e5e7eb; font-size: 13px; outline: none; }
    .search-row input[type=text]:focus { border-color: #00ffaa; box-shadow: 0 0 0 1px rgba(0,255,170,0.4); }
    .search-row button { padding: 8px 12px; border-radius: 8px; border: none; background: #16a34a; color: white; font-size: 13px; cursor: pointer; }
    .search-row button:hover { background: #22c55e; box-shadow: 0 0 10px rgba(34,197,94,0.6); }
    .pill { display:inline-block; padding: 2px 8px; border-radius: 999px; font-size: 11px; border: 1px solid #0f172a; background: rgba(0,255,170,0.06); color:#a7ffdf; }
    .pill a { color:#a7ffdf; }
    .phc { font-family: ui-monospace, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; word-break: break-all; }
    footer { text-align: center; font-size: 11px; color: #6b7280; padding-bottom: 32px; }
    .kv { display:grid; grid-template-columns: 160px 1fr; gap: 6px 14px; margin-top: 10px; }
    .kv div { font-size: 13px; }
    .kv .k { color:#9ca3af; }
    .metrics { margin-top: 12px; display:flex; gap:18px; flex-wrap:wrap; align-items:flex-start; }
    .metric-box { min-width: 220px; }
    .chart-wrap { width: 100%; max-width: 100%; overflow: hidden; border-radius: 10px; }
    canvas {
      display: block;
      width: 100% !important;
      height: 190px !important;
      border: 1px solid #0f172a;
      border-radius: 10px;
      background: rgba(2,6,23,0.35);
      box-sizing: border-box;
    }
    .copyable { cursor:pointer; }
  </style>
</head>
<body>
  <header>
    <div class="header-left">
      <img src="{{ url_for('static', filename='phoncoin_logo.png') }}" alt="PHONCOIN" class="logo">
      <div>
        <div class="title"><a href="{{ url_for('explorer') }}">PHONCOIN - EXPLORER</a></div>
        <div class="subtitle">{{ chain_name }} - {{ consensus }}</div>
      </div>
    </div>

    <div class="stats">
      Height {{ height }}<br>
      Issued {{ "%.6f" % total_issued_phc }} {{ ticker }}
    </div>
  </header>

  <div class="container">
    {{ content|safe }}
  </div>
  <footer>
    PHONCOIN · Proof-of-Phone (PoP Secure v4.1)
  </footer>

  <script>
    // ✅ Copy-to-clipboard (mobile friendly) + toast
    function copyText(txt) {
      if (!txt) return;
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(txt).then(() => showToast('Copié ✓')).catch(() => fallbackCopy(txt));
      } else {
        fallbackCopy(txt);
      }
    }
    function fallbackCopy(txt) {
      const ta = document.createElement('textarea');
      ta.value = txt;
      ta.style.position = 'fixed';
      ta.style.left = '-9999px';
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand('copy'); } catch(e) {}
      document.body.removeChild(ta);
      showToast('Copié ✓');
    }
    function showToast(msg) {
      let t = document.getElementById('toast');
      if (!t) {
        t = document.createElement('div');
        t.id = 'toast';
        t.style.cssText = `
          position:fixed; bottom:24px; left:50%; transform:translateX(-50%);
          background:#16a34a; color:white; padding:8px 14px;
          border-radius:999px; font-size:13px;
          box-shadow:0 6px 20px rgba(0,0,0,.5);
          z-index:9999; opacity:0; transition:.25s`;
        document.body.appendChild(t);
      }
      t.textContent = msg;
      t.style.opacity = '1';
      setTimeout(()=>t.style.opacity='0', 1200);
    }
  </script>

</body>
</html>
"""


def _explorer_header_vars() -> Dict[str, Any]:
    height = len(node.chain) - 1
    total_issued_phc = node.total_issued_raw / float(SCALE_RAW_PER_PHC)
    return {
        "chain_name": CHAIN_NAME,
        "ticker": TICKER,
        "consensus": CONSENSUS_NAME,
        "height": height,
        "total_issued_phc": total_issued_phc,
    }


def _get_block(idx: int) -> Optional[Block]:
    if idx < 0 or idx >= len(node.chain):
        return None
    return node.chain[idx]


@app.route("/explorer")
def explorer():
    height = len(node.chain) - 1

    rows = []
    for b in reversed(node.chain[-80:]):
        block_url = url_for("explorer_block", height=b.index)
        rows.append(
            "<tr>"
            f"<td class='phc'><a href='{block_url}'>{b.index}</a></td>"
            f"<td class='phc'><a href='{block_url}'>{short_hex(b.block_hash, 16)}</a></td>"
            f"<td class='phc'>{short_hex(b.prev_hash, 16)}</td>"
            f"<td>{fmt_utc(b.timestamp)}</td>"
            f"<td>{len(b.heartbeats)}</td>"
            f"<td>{len(b.transactions)}</td>"
            "</tr>"
        )

    holders = node.holders_count()
    active_miners = node.active_miners(ACTIVE_MINERS_WINDOW_SEC)

    recent_txs = node.db.load_recent_txs(25)
    tx_rows = []
    for tx in recent_txs:
        tx_url = url_for("explorer_tx", txid=tx["txid"])
        from_url = url_for("explorer_address", address=tx["from_pubkey"])
        to_url = url_for("explorer_address", address=tx["to_pubkey"])
        tx_rows.append(
            "<tr>"
            f"<td class='phc'><a href='{tx_url}'>{short_hex(tx['txid'], 18)}</a></td>"
            f"<td class='phc'><a href='{from_url}'>{short_hex(tx['from_pubkey'], 18)}</a></td>"
            f"<td class='phc'><a href='{to_url}'>{short_hex(tx['to_pubkey'], 18)}</a></td>"
            f"<td>{tx['amount_raw']/float(SCALE_RAW_PER_PHC):.6f} {TICKER}</td>"
            f"<td>{fmt_utc(tx['timestamp'])}</td>"
            f"<td class='phc'>{tx.get('block_idx','')}</td>"
            "</tr>"
        )


    # ✅ L2 pending txs (mempool)
    with node.lock:
        pending = list(node.txpool[-80:])  # last 80 pending
    pending_rows_list = []
    now_ts = int(time.time())
    for t in reversed(pending):
        tx_url = url_for("explorer_tx", txid=t.txid)
        from_url = url_for("explorer_address", address=t.from_pubkey)
        to_url = url_for("explorer_address", address=t.to_pubkey)
        age_s = max(0, now_ts - int(t.timestamp))
        pending_rows_list.append(
            "<tr>"
            f"<td class='phc'><a href='{tx_url}'>{short_hex(t.txid, 18)}</a></td>"
            f"<td class='phc'><a href='{from_url}'>{short_hex(t.from_pubkey, 18)}</a></td>"
            f"<td class='phc'><a href='{to_url}'>{short_hex(t.to_pubkey, 18)}</a></td>"
            f"<td>{t.amount/float(SCALE_RAW_PER_PHC):.6f} {TICKER}</td>"
            f"<td>{age_s}s</td>"
            "</tr>"
        )
    pending_rows = ''.join(pending_rows_list) if pending_rows_list else "<tr><td colspan='5' class='muted'>Aucune transaction en attente</td></tr>"

    content = f"""
    <div class="card">
      <h2>Réseau</h2>
      <div class="muted">
        Node: <span class="phc">/network_info</span> ·
        Chain height: <span class="phc">{height}</span>
        · <span class="pill"><a href="/explorer/holders">Top Holders</a></span>
        · <span class="pill"><a href="/explorer/miners">Top Mineurs</a></span>
        · <span class="pill"><a href="/explorer/blocks">Tous les blocs</a></span>
        · <span class="pill"><a href="/explorer/txs">Toutes les TX</a></span>
        · <span class="pill">HB mempool: {len(node.mempool)}</span>
        · <span class="pill">TX mempool: {len(node.txpool)}</span>
      </div>

      <div class="metrics">
        <div class="metric-box">
          <div class="muted">Holders (solde &gt; 0)</div>
          <div style="font-size:22px; font-weight:700; color:#a7ffdf;">{holders}</div>
        </div>
        <div class="metric-box">
          <div class="muted">Mineurs actifs (10 min)</div>
          <div style="font-size:22px; font-weight:700; color:#a7ffdf;">{active_miners}</div>
        </div>
        <div class="metric-box" style="flex:1; min-width:360px;">
          <div class="muted">Graphe PRO (courbes normalisées) — derniers blocs</div>
          <div class="chart-wrap"><canvas id="phcChart"></canvas></div>
          <div class="muted" style="margin-top:6px;">Source: <span class="phc">/metrics</span></div>
        </div>
      </div>

      <div class="search-row">
        <form action="{url_for('explorer_search')}" method="get" style="display:flex; gap:8px; flex-wrap:wrap; align-items:center;">
          <input type="text" name="q" placeholder="Recherche: height / hash / txid / adresse..." />
          <button type="submit">Chercher</button>
          <span class="pill">Astuce: clique/tap sur une adresse pour copier</span>
        </form>
      </div>
    </div>

    <div class="card">
      <h2>Derniers blocs</h2>
      <table>
        <thead>
          <tr>
            <th>Height</th>
            <th>Hash</th>
            <th>Prev</th>
            <th>Timestamp (UTC)</th>
            <th>HB</th>
            <th>TX</th>
          </tr>
        </thead>
        <tbody>
          {''.join(rows) if rows else '<tr><td colspan="6" class="muted">Aucun bloc</td></tr>'}
        </tbody>
      </table>
    </div>

    <div class="card">
      <h2>Dernières transactions (on-chain)</h2>
      <div class="muted">Affiche les TX incluses dans des blocs (table txs).</div>
      <table>
        <thead>
          <tr>
            <th>TxID</th>
            <th>From</th>
            <th>To</th>
            <th>Montant</th>
            <th>Timestamp (UTC)</th>
            <th>Bloc</th>
          </tr>
        </thead>
        <tbody>
          {''.join(tx_rows) if tx_rows else '<tr><td colspan="6" class="muted">Aucune transaction encore</td></tr>'}
        </tbody>
      </table>
    </div>


    <div class="card">
      <h2>Transactions en attente (L2 mempool)</h2>
      <div class="muted">Acceptées instantanément (L2), finalisées quand elles entrent dans un bloc (L1).</div>
      <table>
        <thead>
          <tr>
            <th>TxID</th>
            <th>From</th>
            <th>To</th>
            <th>Montant</th>
            <th>Age</th>
          </tr>
        </thead>
        <tbody>
          {pending_rows}
        </tbody>
      </table>
    </div>

    <script>
    (function() {{
      const canvas = document.getElementById('phcChart');
      if (!canvas) return;

      function resizeCanvas() {{
        const rect = canvas.getBoundingClientRect();
        const dpr = window.devicePixelRatio || 1;
        const w = Math.max(360, Math.floor(rect.width));
        const h = 190;
        canvas.width = Math.floor(w * dpr);
        canvas.height = Math.floor(h * dpr);
        const ctx = canvas.getContext('2d');
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        return ctx;
      }}

      let ctx = resizeCanvas();

      // Stable redraw (no double legend / no overlap during fullscreen or DPI changes)
      let drawing = false;
      let scheduled = false;
      function scheduleDraw() {{
        if (scheduled) return;
        scheduled = true;
        requestAnimationFrame(() => {{
          scheduled = false;
          load();
        }});
      }}

      window.addEventListener('resize', () => {{
        ctx = resizeCanvas();
        scheduleDraw();
      }});

      function clear() {{
        // Clear using internal pixel size (robust for fullscreen + DPR)
        ctx.save();
        ctx.setTransform(1, 0, 0, 1, 0, 0);
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        ctx.restore();
      }}

      // Chart layout (reserve space for legend/title so lines never overlap text)
      const TOP_MARGIN = 54;     // reserved for legend
      const BOTTOM_MARGIN = 22;  // x-axis baseline
      const LEFT_MARGIN = 36;
      const RIGHT_MARGIN = 10;

      function drawAxes() {{
        const W = canvas.getBoundingClientRect().width;
        const H = 190;
        ctx.globalAlpha = 0.85;
        ctx.strokeStyle = '#0f172a';
        ctx.lineWidth = 1;

        // Y + X axis (inside margins)
        ctx.beginPath();
        ctx.moveTo(LEFT_MARGIN, TOP_MARGIN);
        ctx.lineTo(LEFT_MARGIN, H - BOTTOM_MARGIN);
        ctx.lineTo(W - RIGHT_MARGIN, H - BOTTOM_MARGIN);
        ctx.stroke();

        // subtle horizontal grid lines
        ctx.globalAlpha = 0.25;
        const usableH = (H - TOP_MARGIN - BOTTOM_MARGIN);
        for (let i = 1; i <= 3; i++) {{
          const y = TOP_MARGIN + (i * usableH / 4);
          ctx.beginPath();
          ctx.moveTo(LEFT_MARGIN, y);
          ctx.lineTo(W - RIGHT_MARGIN, y);
          ctx.stroke();
        }}
        ctx.globalAlpha = 1;
      }}

      function plotLine01(values01, color) {{
        const W = canvas.getBoundingClientRect().width;
        const H = 190;

        const usableW = W - LEFT_MARGIN - RIGHT_MARGIN;
        const usableH = H - TOP_MARGIN - BOTTOM_MARGIN;

        const x0 = LEFT_MARGIN;
        const y0 = H - BOTTOM_MARGIN;

        const n = values01.length;
        if (n < 2) return;

        ctx.strokeStyle = color;
        ctx.lineWidth = 2;
        ctx.beginPath();

        for (let i = 0; i < n; i++) {{
          const x = x0 + (i * (usableW / (n - 1)));
          const t = Math.max(0, Math.min(1, values01[i])); // clamp 0..1
          const y = y0 - (t * usableH);
          if (i === 0) ctx.moveTo(x, y);
          else ctx.lineTo(x, y);
        }}
        ctx.stroke();
      }}

      function normalize(values) {{
        let vmax = 0;
        for (const v of values) vmax = Math.max(vmax, Number(v)||0);
        const denom = Math.max(1, vmax);
        return {{
          max: vmax,
          vals01: values.map(v => (Number(v)||0) / denom)
        }};
      }}

      function drawLegend(items) {{
  // Legend area is ABOVE the plot, never overlaps lines.
  // We support wrapping on small screens by moving to next line.
  const W = canvas.getBoundingClientRect().width;

  ctx.font = '12px system-ui, -apple-system, Segoe UI, sans-serif';

  // background "glass" bar behind legend for readability
  ctx.save();
  ctx.globalAlpha = 0.55;
  ctx.fillStyle = '#020617';
  ctx.fillRect(LEFT_MARGIN + 1, 8, W - LEFT_MARGIN - RIGHT_MARGIN - 2, TOP_MARGIN - 10);
  ctx.restore();

  let x = LEFT_MARGIN + 10;
  let y = 20;
  const lineH = 16;

  for (const it of items) {{
    const label = String(it.label || '');
    const swatchW = 10;
    const pad = 8;

    // measure label width to decide wrap
    const labelW = ctx.measureText(label).width;
    const itemW = swatchW + 4 + labelW + pad;

    if (x + itemW > W - RIGHT_MARGIN) {{
      x = LEFT_MARGIN + 10;
      y += lineH;
    }}

    ctx.fillStyle = it.color;
    ctx.fillRect(x, y - 10, swatchW, swatchW);

    ctx.fillStyle = '#e5e7eb';
    ctx.fillText(label, x + swatchW + 6, y);

    x += itemW + 10;
  }}
}}

      async function load() {{
        if (drawing) return;
        drawing = true;
        try {{
          const r = await fetch('/metrics?n=120', {{ cache: 'no-store' }});
          const j = await r.json();
          if (!j || !j.ok || !j.series) return;

          const s = j.series;
          const diff = s.map(x => x.difficulty_zeros);
          const miners = s.map(x => x.unique_miners);
          const hb = s.map(x => x.hb);
          const tx = s.map(x => x.tx);

          const nd = normalize(diff);
          const nm = normalize(miners);
          const nh = normalize(hb);
          const nt = normalize(tx);

          clear();
          drawAxes();

          plotLine01(nh.vals01, '#22c55e');   // HB
          plotLine01(nm.vals01, '#00ffaa');   // miners
          plotLine01(nd.vals01, '#60a5fa');   // diff
          plotLine01(nt.vals01, '#f59e0b');   // tx

          drawLegend([
            {{ label:`HB (max ${'{'}nh.max{'}'})`, color:'#22c55e' }},
            {{ label:`Mineurs (max ${'{'}nm.max{'}'})`, color:'#00ffaa' }},
            {{ label:`Diff (max ${'{'}nd.max{'}'})`, color:'#60a5fa' }},
            {{ label:`TX (max ${'{'}nt.max{'}'})`, color:'#f59e0b' }}
          ]);
        }} catch (e) {{}} finally {{ drawing = false; }}
      }}

      load();
      setInterval(load, 15000);
    }})();
    </script>
    """

    return render_template_string(EXPLORER_BASE_TEMPLATE, content=content, **_explorer_header_vars())



@app.route("/explorer/blocks")
def explorer_blocks():
    # Paginated blocks list (newest first)
    try:
        page = int(request.args.get("page", "1"))
    except Exception:
        page = 1
    page = max(1, page)
    try:
        per = int(request.args.get("per", "50"))
    except Exception:
        per = 50
    per = max(10, min(per, 200))

    height = len(node.chain) - 1
    total = height + 1  # includes genesis
    end = total - (page - 1) * per
    start = max(0, end - per)
    if end < 0:
        end = 0
    if start > end:
        start = max(0, end - per)

    subset = node.chain[start:end]
    subset = list(reversed(subset))  # newest first

    rows = []
    for b in subset:
        block_url = url_for("explorer_block", height=b.index)
        rows.append(
            "<tr>"
            f"<td class='phc'><a href='{block_url}'>{b.index}</a></td>"
            f"<td class='phc'><a href='{block_url}'>{short_hex(b.block_hash, 16)}</a></td>"
            f"<td class='phc'>{short_hex(b.prev_hash, 16)}</td>"
            f"<td>{fmt_utc(b.timestamp)}</td>"
            f"<td>{len(b.heartbeats)}</td>"
            f"<td>{len(b.transactions)}</td>"
            "</tr>"
        )

    older_link = url_for("explorer_blocks", page=page + 1, per=per) if start > 0 else ""
    newer_link = url_for("explorer_blocks", page=page - 1, per=per) if page > 1 else ""
    latest_link = url_for("explorer_blocks", page=1, per=per)

    content = f"""
    <div class="card">
      <h2>Blocs (paginated)</h2>
      <div class="muted">
        <a href="{url_for('explorer')}">← Dashboard</a>
        &nbsp;·&nbsp;
        <a href="{latest_link}">Derniers</a>
        {'&nbsp;·&nbsp;<a href="'+newer_link+'">Plus récents</a>' if newer_link else ''}
        {'&nbsp;·&nbsp;<a href="'+older_link+'">Plus anciens</a>' if older_link else ''}
      </div>

      <div class="search-row">
        <form action="{url_for('explorer_search')}" method="get" style="display:flex; gap:8px; flex-wrap:wrap; align-items:center;">
          <input type="text" name="q" placeholder="Jump: height / hash / txid / adresse..." />
          <button type="submit">Aller</button>
          <span class="pill">Page {page} · {per}/page · Height {height}</span>
        </form>
      </div>

      <table>
        <thead>
          <tr>
            <th>Height</th>
            <th>Hash</th>
            <th>Prev</th>
            <th>Timestamp (UTC)</th>
            <th>HB</th>
            <th>TX</th>
          </tr>
        </thead>
        <tbody>
          {''.join(rows) if rows else '<tr><td colspan="6" class="muted">Aucun bloc</td></tr>'}
        </tbody>
      </table>
    </div>
    """
    return render_template_string(EXPLORER_BASE_TEMPLATE, content=content, **_explorer_header_vars())


@app.route("/explorer/txs")
def explorer_txs():
    # Paginated on-chain transactions (newest first)
    try:
        page = int(request.args.get("page", "1"))
    except Exception:
        page = 1
    page = max(1, page)
    try:
        per = int(request.args.get("per", "50"))
    except Exception:
        per = 50
    per = max(10, min(per, 200))

    offset = (page - 1) * per
    txs = node.db.load_txs_page(limit=per, offset=offset)

    tx_rows = []
    for tx in txs:
        tx_url = url_for("explorer_tx", txid=tx["txid"])
        from_url = url_for("explorer_address", address=tx["from_pubkey"])
        to_url = url_for("explorer_address", address=tx["to_pubkey"])
        tx_rows.append(
            "<tr>"
            f"<td class='phc'><a href='{tx_url}'>{short_hex(tx['txid'], 18)}</a></td>"
            f"<td class='phc'><a href='{from_url}'>{short_hex(tx['from_pubkey'], 18)}</a></td>"
            f"<td class='phc'><a href='{to_url}'>{short_hex(tx['to_pubkey'], 18)}</a></td>"
            f"<td>{tx['amount_raw']/float(SCALE_RAW_PER_PHC):.6f} {TICKER}</td>"
            f"<td>{fmt_utc(tx['timestamp'])}</td>"
            f"<td class='phc'>{tx.get('block_idx','')}</td>"
            "</tr>"
        )

    older_link = url_for("explorer_txs", page=page + 1, per=per) if len(txs) == per else ""
    newer_link = url_for("explorer_txs", page=page - 1, per=per) if page > 1 else ""
    latest_link = url_for("explorer_txs", page=1, per=per)

    content = f"""
    <div class="card">
      <h2>Transactions on-chain (paginated)</h2>
      <div class="muted">
        <a href="{url_for('explorer')}">← Dashboard</a>
        &nbsp;·&nbsp;
        <a href="{latest_link}">Dernières</a>
        {'&nbsp;·&nbsp;<a href="'+newer_link+'">Plus récentes</a>' if newer_link else ''}
        {'&nbsp;·&nbsp;<a href="'+older_link+'">Plus anciennes</a>' if older_link else ''}
      </div>

      <div class="search-row">
        <form action="{url_for('explorer_search')}" method="get" style="display:flex; gap:8px; flex-wrap:wrap; align-items:center;">
          <input type="text" name="q" placeholder="Recherche: txid / height / adresse..." />
          <button type="submit">Aller</button>
          <span class="pill">Page {page} · {per}/page</span>
        </form>
      </div>

      <table>
        <thead>
          <tr>
            <th>TxID</th>
            <th>From</th>
            <th>To</th>
            <th>Montant</th>
            <th>Timestamp (UTC)</th>
            <th>Bloc</th>
          </tr>
        </thead>
        <tbody>
          {''.join(tx_rows) if tx_rows else '<tr><td colspan="6" class="muted">Aucune transaction</td></tr>'}
        </tbody>
      </table>
    </div>
    """
    return render_template_string(EXPLORER_BASE_TEMPLATE, content=content, **_explorer_header_vars())

@app.route("/explorer/search")
def explorer_search():
    q = (request.args.get("q") or "").strip()
    if not q:
        return redirect(url_for("explorer"))

    if q.isdigit():
        return redirect(url_for("explorer_block", height=int(q)))

    if len(q) >= 32 and all(c in "0123456789abcdefABCDEF" for c in q):
        ql = q.lower()
        tx = node.db.load_tx_by_txid(ql)
        if tx:
            return redirect(url_for("explorer_tx", txid=ql))
        for b in node.chain:
            if b.block_hash == ql:
                return redirect(url_for("explorer_block", height=b.index))
        return redirect(url_for("explorer_address", address=q))

    return redirect(url_for("explorer_address", address=q))


@app.route("/explorer/holders")
def explorer_holders():
    total = node.total_issued_raw
    rows = sorted(node.balances.items(), key=lambda x: x[1], reverse=True)[:200]

    trs = []
    for i, (addr, raw) in enumerate(rows, 1):
        phc = raw / float(SCALE_RAW_PER_PHC)
        pct = (raw / total * 100.0) if total > 0 else 0.0
        trs.append(
            "<tr>"
            f"<td>{i}</td>"
            f"<td class='phc copyable' onclick=\"copyText('{addr}')\">{addr}</td>"
            f"<td>{phc:.6f} {TICKER}</td>"
            f"<td>{pct:.6f}%</td>"
            "</tr>"
        )

    content = f"""
    <div class="card">
      <h2>Top Holders</h2>
      <div class="muted"><a href="{url_for('explorer')}">← Retour</a> · Clique/tap sur une adresse pour copier</div>
      <table>
        <thead>
          <tr><th>#</th><th>Adresse</th><th>Solde</th><th>% Supply</th></tr>
        </thead>
        <tbody>
          {''.join(trs) if trs else '<tr><td colspan="4" class="muted">Aucun holder</td></tr>'}
        </tbody>
      </table>
    </div>
    """
    return render_template_string(EXPLORER_BASE_TEMPLATE, content=content, **_explorer_header_vars())


@app.route("/explorer/miners")
def explorer_miners():
    stats: Dict[str, Dict[str, Any]] = {}
    for b in node.chain:
        if not b.heartbeats:
            continue
        for hb in b.heartbeats:
            s = stats.setdefault(hb.pubkey_hex, {"hb": 0, "blocks": set()})
            s["hb"] += 1
            s["blocks"].add(b.index)

    rows = sorted(stats.items(), key=lambda x: x[1]["hb"], reverse=True)[:200]

    trs = []
    for i, (addr, s) in enumerate(rows, 1):
        trs.append(
            "<tr>"
            f"<td>{i}</td>"
            f"<td class='phc copyable' onclick=\"copyText('{addr}')\">{addr}</td>"
            f"<td>{s['hb']}</td>"
            f"<td>{len(s['blocks'])}</td>"
            f"</tr>"
        )

    content = f"""
    <div class="card">
      <h2>Top Mineurs PoP</h2>
      <div class="muted"><a href="{url_for('explorer')}">← Retour</a> · Classement par heartbeats on-chain</div>
      <table>
        <thead>
          <tr><th>#</th><th>Adresse</th><th>HB</th><th>Blocs</th></tr>
        </thead>
        <tbody>
          {''.join(trs) if trs else '<tr><td colspan="4" class="muted">Aucun mineur</td></tr>'}
        </tbody>
      </table>
    </div>
    """
    return render_template_string(EXPLORER_BASE_TEMPLATE, content=content, **_explorer_header_vars())


@app.route("/explorer/block/<int:height>")
def explorer_block(height: int):
    b = _get_block(height)
    if b is None:
        return redirect(url_for("explorer"))

    reward_raw = node.block_reward_raw(b.index)
    unique_clients = sorted(list({hb.pubkey_hex for hb in b.heartbeats}))
    per_raw = (reward_raw // len(unique_clients)) if unique_clients else 0

    miner_counts: Dict[str, int] = {}
    for hb in b.heartbeats:
        miner_counts[hb.pubkey_hex] = miner_counts.get(hb.pubkey_hex, 0) + 1

    miners_rows = []
    for pk in sorted(miner_counts.keys(), key=lambda x: miner_counts[x], reverse=True):
        miners_rows.append(
            "<tr>"
            f"<td class='phc copyable' onclick=\"copyText('{pk}')\">{pk}</td>"
            f"<td>{miner_counts[pk]}</td>"
            f"<td>{per_raw / float(SCALE_RAW_PER_PHC):.6f} {TICKER}</td>"
            f"<td class='phc'>{per_raw}</td>"
            "</tr>"
        )

    hb_rows = []
    for i, hb in enumerate(b.heartbeats[:800]):
        hb_rows.append(
            "<tr>"
            f"<td class='phc'>{i}</td>"
            f"<td class='phc copyable' onclick=\"copyText('{hb.pubkey_hex}')\">{hb.pubkey_hex}</td>"
            f"<td>{fmt_utc(hb.timestamp)}</td>"
            f"<td class='phc'>{short_hex(hb.device_fingerprint, 18)}</td>"
            f"<td>{hb.latency_ms}</td>"
            f"<td class='phc'>{short_hex(hb.nonce, 18)}</td>"
            "</tr>"
        )

    tx_rows = []
    for i, tx in enumerate(b.transactions[:800]):
        tx_url = url_for("explorer_tx", txid=tx.txid)
        tx_rows.append(
            "<tr>"
            f"<td class='phc'>{i}</td>"
            f"<td class='phc'><a href='{tx_url}'>{tx.txid}</a></td>"
            f"<td class='phc copyable' onclick=\"copyText('{tx.from_pubkey}')\">{short_hex(tx.from_pubkey, 24)}</td>"
            f"<td class='phc copyable' onclick=\"copyText('{tx.to_pubkey}')\">{short_hex(tx.to_pubkey, 24)}</td>"
            f"<td>{tx.amount/float(SCALE_RAW_PER_PHC):.6f} {TICKER}</td>"
            f"<td>{fmt_utc(tx.timestamp)}</td>"
            "</tr>"
        )

    prev_link = url_for("explorer_block", height=max(b.index - 1, 0))
    next_link = url_for("explorer_block", height=min(b.index + 1, len(node.chain) - 1))

    meta = node.block_meta.get(b.index, {})
    diff_at_block = int(meta.get("difficulty_zeros", node.difficulty_zeros))

    content = f"""
    <div class="card">
      <h2>Bloc #{b.index}</h2>
      <div class="muted">
        <a href="{url_for('explorer')}">← Retour</a>
        &nbsp;·&nbsp;
        <a href="{prev_link}">Bloc précédent</a>
        &nbsp;·&nbsp;
        <a href="{next_link}">Bloc suivant</a>
      </div>

      <div class="kv">
        <div class="k">Hash</div><div class="phc copyable" onclick="copyText('{b.block_hash}')">{b.block_hash}</div>
        <div class="k">Prev hash</div><div class="phc copyable" onclick="copyText('{b.prev_hash}')">{b.prev_hash}</div>
        <div class="k">Timestamp</div><div>{fmt_utc(b.timestamp)} <span class="muted">(UTC)</span></div>
        <div class="k">Heartbeats</div><div>{len(b.heartbeats)}</div>
        <div class="k">Transactions</div><div>{len(b.transactions)}</div>
        <div class="k">Difficulty zeros</div><div>{diff_at_block}</div>
        <div class="k">Reward (block)</div><div>{reward_raw / float(SCALE_RAW_PER_PHC):.6f} {TICKER} <span class="muted">({reward_raw} raw)</span></div>
        <div class="k">Reward / mineur</div><div>{per_raw / float(SCALE_RAW_PER_PHC):.6f} {TICKER} <span class="muted">({per_raw} raw)</span></div>
        <div class="k">Mineurs uniques</div><div>{len(unique_clients)}</div>
      </div>
    </div>

    <div class="card">
      <h2>Transactions du bloc</h2>
      <div class="muted">Affichage des 800 premières max.</div>
      <table>
        <thead>
          <tr>
            <th>#</th>
            <th>TxID</th>
            <th>From</th>
            <th>To</th>
            <th>Montant</th>
            <th>Timestamp</th>
          </tr>
        </thead>
        <tbody>
          {''.join(tx_rows) if tx_rows else '<tr><td colspan="6" class="muted">Aucune transaction dans ce bloc</td></tr>'}
        </tbody>
      </table>
    </div>

    <div class="card">
      <h2>Mineurs du bloc</h2>
      <div class="muted">Clique/tap sur une adresse pour copier.</div>
      <table>
        <thead>
          <tr>
            <th>Adresse (pubkey)</th>
            <th>HB dans ce bloc</th>
            <th>Reward estimée</th>
            <th>Reward raw</th>
          </tr>
        </thead>
        <tbody>
          {''.join(miners_rows) if miners_rows else '<tr><td colspan="4" class="muted">Bloc vide</td></tr>'}
        </tbody>
      </table>
    </div>

    <div class="card">
      <h2>Heartbeats du bloc</h2>
      <div class="muted">Affichage des 800 premiers max.</div>
      <table>
        <thead>
          <tr>
            <th>#</th>
            <th>Pubkey</th>
            <th>Timestamp</th>
            <th>Fingerprint</th>
            <th>Latency</th>
            <th>Nonce</th>
          </tr>
        </thead>
        <tbody>
          {''.join(hb_rows) if hb_rows else '<tr><td colspan="6" class="muted">Aucun heartbeat</td></tr>'}
        </tbody>
      </table>
    </div>
    """
    return render_template_string(EXPLORER_BASE_TEMPLATE, content=content, **_explorer_header_vars())


@app.route("/explorer/tx/<txid>")
def explorer_tx(txid: str):
    txid = (txid or "").strip().lower()
    tx = node.db.load_tx_by_txid(txid)
    if not tx:
        return redirect(url_for("explorer"))

    blk = tx.get("block_idx")
    blk_link = url_for("explorer_block", height=int(blk)) if blk is not None else url_for("explorer")

    amt_phc = tx["amount_raw"] / float(SCALE_RAW_PER_PHC)

    content = f"""
    <div class="card">
      <h2>Transaction</h2>
      <div class="muted"><a href="{url_for('explorer')}">← Retour</a></div>

      <div class="kv">
        <div class="k">TxID</div><div class="phc copyable" onclick="copyText('{tx["txid"]}')">{tx["txid"]}</div>
        <div class="k">Bloc</div><div><a class="phc" href="{blk_link}">{blk}</a></div>
        <div class="k">Timestamp</div><div>{fmt_utc(tx["timestamp"])} <span class="muted">(UTC)</span></div>
        <div class="k">From</div><div class="phc copyable" onclick="copyText('{tx["from_pubkey"]}')">{tx["from_pubkey"]}</div>
        <div class="k">To</div><div class="phc copyable" onclick="copyText('{tx["to_pubkey"]}')">{tx["to_pubkey"]}</div>
        <div class="k">Amount</div><div>{amt_phc:.6f} {TICKER} <span class="muted">({tx["amount_raw"]} raw)</span></div>
        <div class="k">Signature</div><div class="phc copyable" onclick="copyText('{tx["signature"]}')">{tx["signature"]}</div>
      </div>
    </div>
    """
    return render_template_string(EXPLORER_BASE_TEMPLATE, content=content, **_explorer_header_vars())


@app.route("/explorer/address/<address>")
def explorer_address(address: str):
    raw = node.balances.get(address, 0)
    phc = raw / float(SCALE_RAW_PER_PHC)

    seen_hb = []
    for b in reversed(node.chain):
        for hb in b.heartbeats:
            if hb.pubkey_hex == address:
                seen_hb.append((b.index, hb.timestamp, hb.device_fingerprint, hb.latency_ms))
                if len(seen_hb) >= 80:
                    break
        if len(seen_hb) >= 80:
            break

    hb_rows = []
    for (blk_idx, hb_ts, fp, lat) in seen_hb:
        hb_rows.append(
            "<tr>"
            f"<td class='phc'><a href='{url_for('explorer_block', height=blk_idx)}'>{blk_idx}</a></td>"
            f"<td>{fmt_utc(hb_ts)}</td>"
            f"<td class='phc'>{short_hex(fp, 24)}</td>"
            f"<td>{lat}</td>"
            "</tr>"
        )

    seen_tx = node.db.load_recent_txs_for_address(address, limit=80)

    tx_rows = []
    for tx in seen_tx:
        tx_rows.append(
            "<tr>"
            f"<td class='phc'><a href='{url_for('explorer_tx', txid=tx['txid'])}'>{short_hex(tx['txid'], 18)}</a></td>"
            f"<td class='phc'>{short_hex(tx['from_pubkey'], 18)}</td>"
            f"<td class='phc'>{short_hex(tx['to_pubkey'], 18)}</td>"
            f"<td>{tx['amount_raw']/float(SCALE_RAW_PER_PHC):.6f} {TICKER}</td>"
            f"<td>{fmt_utc(tx['timestamp'])}</td>"
            f"<td class='phc'>{tx.get('block_idx','')}</td>"
            "</tr>"
        )


    # ✅ pending txs for this address (L2)
    with node.lock:
        pending_addr = [t for t in node.txpool if t.from_pubkey == address or t.to_pubkey == address]
    pending_addr = pending_addr[-80:]
    pending_rows_addr = []
    now_ts = int(time.time())
    for t in reversed(pending_addr):
        tx_url = url_for("explorer_tx", txid=t.txid)
        age_s = max(0, now_ts - int(t.timestamp))
        pending_rows_addr.append(
            "<tr>"
            f"<td class='phc'><a href='{tx_url}'>{short_hex(t.txid, 18)}</a></td>"
            f"<td class='phc'>{short_hex(t.from_pubkey, 18)}</td>"
            f"<td class='phc'>{short_hex(t.to_pubkey, 18)}</td>"
            f"<td>{t.amount/float(SCALE_RAW_PER_PHC):.6f} {TICKER}</td>"
            f"<td>{age_s}s</td>"
            "</tr>"
        )
    pending_addr_html = ''.join(pending_rows_addr) if pending_rows_addr else "<tr><td colspan='5' class='muted'>Aucune transaction en attente</td></tr>"

    content = f"""
    <div class="card">
      <h2>Adresse</h2>
      <div class="phc copyable" onclick="copyText('{address}')">{address}</div>

      <div style="margin-top:10px;">
        <b>Solde</b> : {phc:.6f} {TICKER} <span class="muted">({raw} raw)</span>
      </div>

      <div style="margin-top:10px;" class="muted">
        Lien direct : <span class="phc">/explorer/address/{address}</span>
      </div>

      <div style="margin-top:10px;" class="muted">
        Wallet API (MetaMask-like) : <span class="phc">/address/{address}/state</span>
      </div>
    </div>

    <div class="card">
      <h2>Transactions en attente (L2)</h2>
      <div class="muted">Acceptées, mais pas encore dans un bloc.</div>
      <table>
        <thead>
          <tr><th>TxID</th><th>From</th><th>To</th><th>Montant</th><th>Age</th></tr>
        </thead>
        <tbody>
          {pending_addr_html}
        </tbody>
      </table>
    </div>

    <div class="card">
      <h2>Transactions récentes (on-chain)</h2>
      <div class="muted">Filtrées sur les dernières TX on-chain.</div>
      <table>
        <thead>
          <tr>
            <th>TxID</th>
            <th>From</th>
            <th>To</th>
            <th>Montant</th>
            <th>Timestamp</th>
            <th>Bloc</th>
          </tr>
        </thead>
        <tbody>
          {''.join(tx_rows) if tx_rows else '<tr><td colspan="6" class="muted">Aucune transaction récente pour cette adresse</td></tr>'}
        </tbody>
      </table>
    </div>

    <div class="card">
      <h2>Derniers heartbeats (on-chain)</h2>
      <table>
        <thead>
          <tr>
            <th>Bloc</th>
            <th>Timestamp (UTC)</th>
            <th>Fingerprint</th>
            <th>Latency ms</th>
          </tr>
        </thead>
        <tbody>
          {''.join(hb_rows) if hb_rows else '<tr><td colspan="4" class="muted">Aucun heartbeat trouvé — il faut attendre un bloc</td></tr>'}
        </tbody>
      </table>
    </div>
    """
    return render_template_string(EXPLORER_BASE_TEMPLATE, content=content, **_explorer_header_vars())


# -------------------------------------------------------------------

if __name__ == "__main__":
    print(f"Starting {CHAIN_NAME} node...")
    print(f"Ticker: {TICKER} | Consensus: {CONSENSUS_NAME}")
    app.run(host="0.0.0.0", port=5000, debug=False)
