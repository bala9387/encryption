# Deploying Quantrace (PS 26237) to Vercel

This deployment runs **real post-quantum cryptography** (liboqs 0.16.0: ML-KEM-768 and
ML-DSA-65), not the classical fallback. Everything below was verified by running
`api/index.py` inside AWS's Python 3.12 Lambda image (Amazon Linux 2023, the OS Vercel
functions run on):

| Check | Result |
|---|---|
| Crypto backend | `liboqs 0.16.0` (real PQC) |
| No password set | every page returns 503 "locked" |
| Wrong / missing credentials | 401 |
| Encrypt once for 3 recipients → decrypt as carol → download | works |
| Cropped + rescaled + JPEG leak → trace | attributed to carol in 12 s (limit set to 60 s) |
| Installed dependencies | 311 MB (Vercel's Python limit: 500 MB) |

---

## How real PQC works on Vercel

Vercel cannot compile C libraries at build time, so a prebuilt one ships in the repo:

- `vendor/oqs/lib/liboqs.so` — liboqs 0.16.0, built on Amazon Linux 2023 with only
  ML-KEM-768 and ML-DSA-65, **no OpenSSL dependency** (it links only against libc).
  568 KB.
- `api/index.py` sets `OQS_INSTALL_PATH` to that folder **before** any crypto import.
- `vercel.json` `includeFiles` makes sure the `.so` is bundled with the function.

If the library ever fails to load, the app does not hide it: `crypto/pqc.py` falls back
to classical X25519/Ed25519, the backend chip reads *"CLASSICAL FALLBACK — NOT
post-quantum"*, and every page shows a red banner. Check for that banner after deploying.

**Rebuilding the library** (only needed when upgrading liboqs):
```bash
docker run --rm -v "$PWD/vendor/oqs:/out" amazonlinux:2023 bash -c '
  dnf install -y git cmake ninja-build gcc &&
  git clone --depth 1 --branch 0.16.0 https://github.com/open-quantum-safe/liboqs /src &&
  cmake -S /src -B /b -GNinja -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON \
    -DOQS_BUILD_ONLY_LIB=ON -DOQS_USE_OPENSSL=OFF -DOQS_DIST_BUILD=ON \
    -DCMAKE_INSTALL_LIBDIR=lib "-DOQS_MINIMAL_BUILD=KEM_ml_kem_768;SIG_ml_dsa_65" \
    -DCMAKE_INSTALL_PREFIX=/opt/oqs &&
  cmake --build /b && cmake --install /b &&
  mkdir -p /out/lib && cp -L /opt/oqs/lib/liboqs.so /out/lib/liboqs.so'
```
Keep it a **regular file, not a symlink** — Git on Windows stores symlinks as text files,
which fail to load on Vercel.

---

## Deploy

### 1. Push to GitHub
```bash
git add -A
git commit -m "Vercel: real PQC via bundled liboqs, password gate"
git push origin main
```

### 2. Import the project
1. [vercel.com/new](https://vercel.com/new) → import **`bala9387/encryption`**.
2. Framework Preset: **Other**. Leave build command and output directory empty.

### 3. Set environment variables — before the first deploy
In **Settings → Environment Variables** (Production):

| Name | Value |
|---|---|
| `PS26237_AUTH_USER` | a username, e.g. `judge` |
| `PS26237_AUTH_PASS` | a strong password |

Without `PS26237_AUTH_PASS` the instance **fails closed**: every page returns a 503 that
explains how to set it. (Set `PS26237_ALLOW_PUBLIC=1` only if you truly want an open demo.)

### 4. Deploy, then verify
Open the `.vercel.app` URL, log in, and check:
- the header chip says **`liboqs 0.16.0`**, and there is **no red "Not post-quantum" banner**;
- Status shows 3 identities (alice, bob, carol).

Demo passphrase for alice, bob and carol: **`password123`** (public — see below).

---

## Limits you must state honestly

1. **The ledger is not persistent.** Each function instance keeps the ledger in its own
   `/tmp`. It is wiped on a cold start, and a trace only finds records committed on the
   same instance. For a live demo, do sender → recipient → trace in one sitting. For a
   persistent ledger, use Cloud Run (`min-instances=1`) or a local install.
2. **The Fabric ledger does not run on Vercel.** The deployment uses the simulated 4-node
   ledger. Show the real 4-organisation Fabric network from a local machine.
3. **Demo identities are public.** `demo_workspace/` holds alice/bob/carol, shared by all
   instances so a package encrypted on one instance decrypts on another. Their passphrase
   is committed to the repository. Never encrypt a real document on this deployment.
4. **A public cloud deployment is a demo, not the product.** PS 26237 requires an
   air-gapped system with no cloud dependency; production deployment is covered in
   `docs/DEPLOYMENT.md`.
5. **Trace time.** A rotated or rescaled leak takes 10–20 s; `maxDuration` is set to 60 s.
