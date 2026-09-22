"""
app/service.py
================

Application layer shared by the CLI (ps26237.py) and the web UI (app/web.py).

A *workspace* directory holds everything for one deployment:
    config.json              {"ledger": "sim" | "fabric"}
    identities/<id>.json     public keys + passphrase-encrypted secret keys
    ledger_sim.pkl           the simulated ledger (only for ledger = "sim")

Secret keys at rest are encrypted with AES-256-GCM under a key derived from
the recipient's passphrase with scrypt (N=2^15, r=8, p=1). This is software
protection for a prototype; see docs/DEPLOYMENT.md for hardware-token/HSM
guidance.

Security rule enforced here: a decrypted, watermarked document is released
ONLY after its signed decryption record has been committed to the ledger.
If the commit fails, decryption output is discarded and an error is raised.
"""

from __future__ import annotations
import base64
import json
import os
import pickle
import re
import threading
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from crypto.pqc import MLKEM, MLDSA, DSAKeyPair, BACKEND
from crypto.document_crypto import EncryptedPackage, encrypt_for_recipients
from crypto.decryption_session import perform_decryption_session
from watermark.document_formats import detect_format, embed_document, extract_candidates, EXTENSIONS, UnsupportedFormat
from forensics.trace_leak import attribute_watermark, AttributionReport

PACKAGE_FORMAT = "ps26237-package-v1"
NODE_IDS = ["sender-org-node", "independent-auditor-node", "security-dept-node", "offsite-backup-node"]
ID_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")


class ServiceError(Exception):
    pass


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _unb64(s: str) -> bytes:
    return base64.b64decode(s)


def _kdf(passphrase: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=2 ** 15, r=8, p=1).derive(passphrase.encode())


@dataclass
class DecryptOutcome:
    filename: str
    data: bytes
    format: str
    record: dict
    committed_on: list
    ledger_ref: str


@dataclass
class TraceOutcome:
    report: AttributionReport
    source: str                        # "image" or "page N"
    candidates_tried: list = field(default_factory=list)

    @property
    def confirmed(self) -> bool:
        return self.report.final_verdict.startswith("CONFIRMED")

    def to_dict(self) -> dict:
        r = self.report
        lk = r.ledger_lookup
        return {
            "verdict": r.final_verdict,
            "confirmed": self.confirmed,
            "source": self.source,
            "extracted_watermark_id": r.watermark_extracted_hex,
            "extraction": r.extraction,
            "match_distance_bits": r.match_distance_bits,
            "ledger": {"found": lk.found, "verified": lk.verified, "quorum_achieved": lk.quorum_achieved,
                       "quorum_needed": lk.quorum_needed, "agreeing_nodes": lk.node_ids_matched},
            "signature_valid": r.signature_valid,
            "record": {k: v for k, v in (lk.record or {}).items() if not k.startswith("_")},
            "candidates_tried": self.candidates_tried,
        }


def resolve_workspace_dir(preferred: str | None = None) -> str:
    """Resolves workspace directory with automatic fallback to /tmp for serverless/read-only hosts."""
    if preferred:
        return preferred
    env_home = os.environ.get("PS26237_HOME")
    if env_home:
        return env_home
    is_serverless = bool(os.environ.get("VERCEL") or os.environ.get("NETLIFY") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME") or os.environ.get("LAMBDA_TASK_ROOT"))
    if is_serverless:
        return "/tmp/ps26237_workspace"
    return "ps26237_workspace"


class Workspace:
    _lock = threading.RLock()

    def __init__(self, root: str | os.PathLike | None = None, ledger: str | None = None):
        target = resolve_workspace_dir(str(root) if root else None)
        try:
            self.root = Path(target)
            self.root.mkdir(parents=True, exist_ok=True)
            (self.root / "identities").mkdir(exist_ok=True)
        except OSError:
            self.root = Path("/tmp/ps26237_workspace")
            self.root.mkdir(parents=True, exist_ok=True)
            (self.root / "identities").mkdir(exist_ok=True)

        cfg_path = self.root / "config.json"
        cfg = json.loads(cfg_path.read_text()) if cfg_path.exists() else {"ledger": "sim"}
        if ledger:
            cfg["ledger"] = ledger
        if cfg["ledger"] not in ("sim", "fabric"):
            raise ServiceError("ledger must be 'sim' or 'fabric'")
        cfg_path.write_text(json.dumps(cfg, indent=1))
        self.config = cfg
        self._ledger = None

    def seed_demo_identities_if_empty(self) -> list[str]:
        """Seeds alice, bob, carol with passphrase 'password123' if no identities exist."""
        with self._lock:
            existing = self.list_identities()
            if existing:
                return []
            created = []
            for name in ["alice", "bob", "carol"]:
                try:
                    self.create_identity(name, "password123")
                    created.append(name)
                except Exception:
                    pass
            return created

    # ------------------------------------------------------------------ ledger
    @property
    def ledger_backend(self) -> str:
        return self.config["ledger"]

    def ledger(self):
        if self._ledger is None:
            if self.ledger_backend == "fabric":
                from ledger.fabric_ledger import FabricLedgerNetwork
                self._ledger = FabricLedgerNetwork()
            else:
                from ledger.ledger_network import LedgerNetwork
                p = self.root / "ledger_sim.pkl"
                self._ledger = pickle.loads(p.read_bytes()) if p.exists() else LedgerNetwork(NODE_IDS, quorum=3)
        return self._ledger

    def _save_ledger(self):
        if self.ledger_backend == "sim" and self._ledger is not None:
            tmp = self.root / "ledger_sim.pkl.tmp"
            tmp.write_bytes(pickle.dumps(self._ledger))
            tmp.replace(self.root / "ledger_sim.pkl")

    def ledger_status(self) -> dict:
        with self._lock:
            led = self.ledger()
            integ = led.verify_network_integrity()
            return {"backend": self.ledger_backend, "nodes": list(led.nodes), "quorum": led.quorum,
                    "records": len(led.all_watermark_ids()), "integrity": integ}

    # -------------------------------------------------------------- identities
    def _identity_path(self, rid: str) -> Path:
        if not ID_RE.match(rid):
            raise ServiceError(f"invalid identity '{rid}' (lowercase letters, digits, . _ -)")
        return self.root / "identities" / f"{rid}.json"

    def create_identity(self, rid: str, passphrase: str) -> dict:
        path = self._identity_path(rid)
        if path.exists():
            raise ServiceError(f"identity '{rid}' already exists")
        if len(passphrase) < 8:
            raise ServiceError("passphrase must be at least 8 characters")
        kem, dsa = MLKEM.keygen(), MLDSA.keygen()
        salt, nonce = os.urandom(16), os.urandom(12)
        secret = json.dumps({"kem_secret_key": _b64(kem.secret_key), "dsa_secret_key": _b64(dsa.secret_key)}).encode()
        ct = AESGCM(_kdf(passphrase, salt)).encrypt(nonce, secret, rid.encode())
        ident = {
            "id": rid,
            "algorithms": {"kem": MLKEM.algorithm, "signature": MLDSA.algorithm, "backend": BACKEND},
            "kem_public_key": _b64(kem.public_key),
            "dsa_public_key": _b64(dsa.public_key),
            "secret_keys": {"kdf": "scrypt-n32768-r8-p1", "cipher": "AES-256-GCM",
                            "salt": _b64(salt), "nonce": _b64(nonce), "ciphertext": _b64(ct)},
        }
        with self._lock:
            if self.ledger_backend == "fabric":
                self.ledger().register_recipient_key(rid, dsa.public_key)
            path.write_text(json.dumps(ident, indent=1))
        return self.public_identity(rid)

    def _load_identity(self, rid: str) -> dict:
        path = self._identity_path(rid)
        if not path.exists():
            raise ServiceError(f"unknown identity '{rid}'")
        return json.loads(path.read_text())

    def public_identity(self, rid: str) -> dict:
        i = self._load_identity(rid)
        return {"id": i["id"], "algorithms": i["algorithms"],
                "kem_public_key_bytes": len(_unb64(i["kem_public_key"])),
                "dsa_public_key_bytes": len(_unb64(i["dsa_public_key"]))}

    def list_identities(self) -> list[str]:
        return sorted(p.stem for p in (self.root / "identities").glob("*.json"))

    def _unlock(self, rid: str, passphrase: str) -> tuple[bytes, DSAKeyPair]:
        i = self._load_identity(rid)
        s = i["secret_keys"]
        try:
            secret = AESGCM(_kdf(passphrase, _unb64(s["salt"]))).decrypt(_unb64(s["nonce"]), _unb64(s["ciphertext"]), rid.encode())
        except Exception:
            raise ServiceError("wrong passphrase") from None
        sk = json.loads(secret)
        return _unb64(sk["kem_secret_key"]), DSAKeyPair(public_key=_unb64(i["dsa_public_key"]),
                                                         secret_key=_unb64(sk["dsa_secret_key"]))

    def signing_directory(self) -> dict:
        return {rid: _unb64(self._load_identity(rid)["dsa_public_key"]) for rid in self.list_identities()}

    # ---------------------------------------------------------------- sender
    def encrypt(self, data: bytes, filename: str, recipients: list[str], document_id: str | None = None) -> bytes:
        detect_format(data)  # reject unsupported formats before distribution
        if not recipients:
            raise ServiceError("at least one recipient required")
        keys = {r: _unb64(self._load_identity(r)["kem_public_key"]) for r in recipients}
        document_id = document_id or f"DOC-{uuid.uuid4().hex[:12].upper()}"
        pkg = encrypt_for_recipients(document_id, data, keys)
        return json.dumps({"format": PACKAGE_FORMAT, "filename": os.path.basename(filename),
                           "package": json.loads(pkg.to_json())}).encode()

    @staticmethod
    def package_info(package_bytes: bytes) -> dict:
        outer = json.loads(package_bytes)
        if outer.get("format") != PACKAGE_FORMAT:
            raise ServiceError("not a PS26237 package")
        p = outer["package"]
        return {"document_id": p["document_id"], "filename": outer["filename"], "recipients": sorted(p["key_wraps"]),
                "ciphertext_bytes": len(_unb64(p["ciphertext"]))}

    # ------------------------------------------------------------- recipient
    def decrypt(self, package_bytes: bytes, rid: str, passphrase: str) -> DecryptOutcome:
        try:
            outer = json.loads(package_bytes)
        except ValueError:
            raise ServiceError("not a PS26237 package") from None
        if outer.get("format") != PACKAGE_FORMAT:
            raise ServiceError("not a PS26237 package")
        pkg = EncryptedPackage.from_json(json.dumps(outer["package"]))
        kem_sk, dsa_kp = self._unlock(rid, passphrase)
        try:
            session = perform_decryption_session(pkg, rid, kem_sk, dsa_kp, raw_image_array=None)
        except PermissionError as e:
            raise ServiceError(str(e)) from None
        except Exception:
            raise ServiceError("decryption failed (wrong key or corrupted package)") from None

        watermarked, fmt = embed_document(session.plaintext_bytes, bytes.fromhex(session.record.watermark_id))

        record = session.record.to_dict()
        record["_signature_hex"] = session.signature_hex
        record["_signer_public_key_hex"] = session.signer_public_key_hex
        with self._lock:
            commit = self.ledger().commit_record(record)
            if not commit.committed:
                raise ServiceError("ledger commit failed -- document NOT released")
            self._save_ledger()

        stem = os.path.splitext(outer["filename"])[0]
        return DecryptOutcome(
            filename=f"{stem}.{rid}{EXTENSIONS[fmt]}", data=watermarked, format=fmt,
            record={k: v for k, v in record.items() if not k.startswith("_")},
            committed_on=commit.node_ids_committed, ledger_ref=commit.block_hash,
        )

    # ------------------------------------------------------------- forensics
    def trace(self, leaked: bytes) -> TraceOutcome:
        candidates = extract_candidates(leaked)
        with self._lock:
            led = self.ledger()
            directory = self.signing_directory()
            tried, first = [], None
            for c in candidates:
                rep = attribute_watermark(c.watermark_id, led, directory,
                                          {"confidence": c.confidence, **c.info})
                tried.append({"source": c.source, "watermark_id": c.watermark_id.hex(),
                              "confidence": round(c.confidence, 3), "verdict": rep.final_verdict.split(" --")[0]})
                outcome = TraceOutcome(rep, c.source, tried)
                if outcome.confirmed:
                    return outcome
                first = first or outcome
            return first
