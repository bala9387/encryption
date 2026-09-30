"""
api/index.py
============

Vercel serverless entrypoint for Quantrace (PS 26237).

What this file does, in order, and why the order matters:

1. Points liboqs-python at the prebuilt vendor/oqs/lib/liboqs.so BEFORE any
   crypto module is imported. That library was built on Amazon Linux 2023
   (Vercel's runtime) and depends only on libc, so the deployed function runs
   real ML-KEM-768 / ML-DSA-65 instead of the classical fallback.
2. Seeds the /tmp workspace from demo_workspace/ (shared, pre-generated demo
   identities). Vercel may run several instances, each with its own /tmp; with
   per-instance random keys, a package encrypted on one instance could not be
   decrypted on another. Shared identity files fix that.
3. Installs the password gate (app/auth.py). On Vercel it fails CLOSED: with no
   PS26237_AUTH_PASS set, every page returns a 503 explaining how to set one.

Known serverless limitation (not fixable without external storage): the
ledger lives in each instance's /tmp. It is lost on cold start, and a trace can
only find records committed on the same instance. Fine for a live demo; for a
persistent ledger use Cloud Run with min-instances=1 or a local install.
"""

import logging
import os
import shutil
import sys

_root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _root_dir not in sys.path:
    sys.path.insert(0, _root_dir)

# 1. Real PQC: must happen before `import oqs` anywhere.
_bundled_oqs = os.path.join(_root_dir, "vendor", "oqs")
if os.path.exists(os.path.join(_bundled_oqs, "lib", "liboqs.so")):
    os.environ.setdefault("OQS_INSTALL_PATH", _bundled_oqs)

os.environ["VERCEL"] = os.environ.get("VERCEL", "1")
os.environ.setdefault("PS26237_HOME", "/tmp/ps26237_workspace")

log = logging.getLogger("quantrace")
logging.basicConfig(level=logging.INFO)

# 2. Shared demo identities (copied once per cold start, never overwritten).
_home = os.environ["PS26237_HOME"]
_seed = os.path.join(_root_dir, "demo_workspace")
if os.path.isdir(_seed) and not os.path.isdir(os.path.join(_home, "identities")):
    shutil.copytree(_seed, _home, dirs_exist_ok=True)

from app.service import Workspace, resolve_workspace_dir  # noqa: E402
from app.web import create_app  # noqa: E402
from app.auth import install_basic_auth  # noqa: E402
from crypto.pqc import BACKEND, IS_REFERENCE_IMPLEMENTATION  # noqa: E402

ws = Workspace(resolve_workspace_dir())
ws.seed_demo_identities_if_empty()   # only runs if the bundle was missing

# Vercel's Python runtime serves the WSGI instance named `app`.
app = create_app(ws)
install_basic_auth(app)

log.info("Quantrace on Vercel | crypto=%s | workspace=%s", BACKEND, ws.root)
if IS_REFERENCE_IMPLEMENTATION:
    log.error("NOT POST-QUANTUM: bundled liboqs failed to load; classical fallback active")
