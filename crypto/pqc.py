"""
crypto/pqc.py
=============

Post-Quantum Cryptography interface layer for PS 26237.

STATUS / HONESTY NOTE -- READ BEFORE ANY DEMO OR SUBMISSION
-----------------------------------------------------------
This module is backed by REAL NIST-standardized post-quantum algorithms
from the Open Quantum Safe `liboqs` C library (via `liboqs-python`):

    - MLKEM.*   -> oqs.KeyEncapsulation("ML-KEM-768")   (FIPS 203)
    - MLDSA.*   -> oqs.Signature("ML-DSA-65")           (FIPS 204)

Key, ciphertext and signature sizes are the genuine lattice-scheme
outputs (1184/2400/1088 B for ML-KEM-768, 1952/4032/3309 B for
ML-DSA-65) -- nothing is padded.

Verified on: Windows 11, Python 3.14.4, liboqs 0.16.0 built from source
with MSVC 14.50 (VS 2026 Build Tools), liboqs-python 0.16.0.

There is NO classical fallback. An earlier revision used X25519/Ed25519
as a size-matched stand-in; that was removed so the system can never
silently run non-quantum-resistant crypto while claiming PQC. If liboqs
is missing, importing this module fails loudly.

What this does NOT claim: FIPS 140-3 validation of the implementation
(liboqs is a research/prototyping library, not a validated module), or
side-channel hardening on this platform.

AIR-GAP NOTE: `liboqs-python` tries to git-clone and build liboqs on
import if it cannot find the shared library. On an air-gapped host,
ship a prebuilt oqs.dll / liboqs.so and point OQS_INSTALL_PATH at it.
"""

from __future__ import annotations
import contextlib
import io
import logging
from dataclasses import dataclass

# liboqs-python attaches its own stdout log handler and prints an INFO banner while
# importing, which would corrupt machine-readable output (e.g. `ps26237 trace --json`).
# Swallow the import-time banner, then keep that logger off stdout for good.
with contextlib.redirect_stdout(io.StringIO()):
    import oqs

_oqs_log = logging.getLogger("oqs.oqs")
_oqs_log.setLevel(logging.WARNING)
for _h in list(_oqs_log.handlers):
    _oqs_log.removeHandler(_h)

# ---------------------------------------------------------------------------
# Parameter sets (real NIST PQC standard sizes; asserted against liboqs below)
# ---------------------------------------------------------------------------

ML_KEM_768 = {
    "name": "ML-KEM-768",
    "nist_level": 3,
    "public_key_bytes": 1184,
    "secret_key_bytes": 2400,
    "ciphertext_bytes": 1088,
    "shared_secret_bytes": 32,
}

ML_DSA_65 = {
    "name": "ML-DSA-65",
    "nist_level": 3,
    "public_key_bytes": 1952,
    "secret_key_bytes": 4032,
    "signature_bytes": 3309,
}

IS_REFERENCE_IMPLEMENTATION = False  # real liboqs lattice crypto is in use
BACKEND = f"liboqs {oqs.oqs_version()}"

with oqs.KeyEncapsulation(ML_KEM_768["name"]) as _k:
    assert _k.details["length_public_key"] == ML_KEM_768["public_key_bytes"]
    assert _k.details["length_secret_key"] == ML_KEM_768["secret_key_bytes"]
    assert _k.details["length_ciphertext"] == ML_KEM_768["ciphertext_bytes"]
with oqs.Signature(ML_DSA_65["name"]) as _s:
    assert _s.details["length_public_key"] == ML_DSA_65["public_key_bytes"]
    assert _s.details["length_secret_key"] == ML_DSA_65["secret_key_bytes"]
    assert _s.details["length_signature"] == ML_DSA_65["signature_bytes"]


# ---------------------------------------------------------------------------
# ML-KEM (Key Encapsulation Mechanism)
# ---------------------------------------------------------------------------

@dataclass
class KEMKeyPair:
    public_key: bytes
    secret_key: bytes
    algorithm: str = ML_KEM_768["name"]


class MLKEM:
    """ML-KEM-768 (FIPS 203) via liboqs."""

    algorithm = ML_KEM_768["name"]

    @staticmethod
    def keygen() -> KEMKeyPair:
        with oqs.KeyEncapsulation(MLKEM.algorithm) as kem:
            pk = kem.generate_keypair()
            sk = kem.export_secret_key()
        return KEMKeyPair(public_key=bytes(pk), secret_key=bytes(sk))

    @staticmethod
    def encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
        """Returns (ciphertext, shared_secret) for the recipient's public key."""
        with oqs.KeyEncapsulation(MLKEM.algorithm) as kem:
            ct, ss = kem.encap_secret(public_key)
        return bytes(ct), bytes(ss)

    @staticmethod
    def decapsulate(ciphertext: bytes, secret_key: bytes) -> bytes:
        """Recovers the shared secret using the recipient's secret key.
        Note: ML-KEM uses implicit rejection -- a wrong key or tampered
        ciphertext yields a pseudorandom secret rather than an error, so
        the AES-GCM tag check downstream is what detects the mismatch."""
        with oqs.KeyEncapsulation(MLKEM.algorithm, secret_key) as kem:
            return bytes(kem.decap_secret(ciphertext))


# ---------------------------------------------------------------------------
# ML-DSA (Digital Signature Algorithm)
# ---------------------------------------------------------------------------

@dataclass
class DSAKeyPair:
    public_key: bytes
    secret_key: bytes
    algorithm: str = ML_DSA_65["name"]


class MLDSA:
    """ML-DSA-65 (FIPS 204) via liboqs."""

    algorithm = ML_DSA_65["name"]

    @staticmethod
    def keygen() -> DSAKeyPair:
        with oqs.Signature(MLDSA.algorithm) as sig:
            pk = sig.generate_keypair()
            sk = sig.export_secret_key()
        return DSAKeyPair(public_key=bytes(pk), secret_key=bytes(sk))

    @staticmethod
    def sign(message: bytes, secret_key: bytes) -> bytes:
        with oqs.Signature(MLDSA.algorithm, secret_key) as sig:
            return bytes(sig.sign(message))

    @staticmethod
    def verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verifies using ONLY the public key and signature (non-repudiation)."""
        try:
            with oqs.Signature(MLDSA.algorithm) as sig:
                return bool(sig.verify(message, signature, public_key))
        except Exception:
            return False
