"""
app/auth.py
=============

HTTP basic auth gate for hosted deployments.

The console has no user model: anyone who reaches it can create identities,
decrypt packages and read the ledger. That is acceptable on 127.0.0.1 behind a
workstation login; it is not acceptable on a public URL. So:

  * On a managed host (Cloud Run sets K_SERVICE), a password is REQUIRED. If
    PS26237_AUTH_PASS is unset the app refuses to start, rather than quietly
    serving an open instance.
  * Locally the gate is optional: set PS26237_AUTH_PASS to switch it on.

This is a demo gate, not an identity system. It is one shared password, checked
in constant time, over whatever TLS the host provides (Cloud Run terminates
HTTPS for you). For anything beyond a judging demo, put a real identity layer
(IAP, SSO) in front — see docs/DEPLOY_GCP.md.
"""

from __future__ import annotations
import hmac
import os

from flask import Response, request

REALM = "Quantrace attribution console"
PUBLIC_PATHS = ("/healthz",)


def _managed_host() -> bool:
    """True on a public hosting platform (Cloud Run, Vercel, Netlify, Lambda)."""
    return bool(os.environ.get("K_SERVICE") or os.environ.get("CLOUD_RUN_JOB")
                or os.environ.get("VERCEL") or os.environ.get("NETLIFY")
                or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"))


NEEDS_PASSWORD_PAGE = """<!doctype html><meta charset="utf-8"><title>Setup required</title>
<body style="font:15px/1.6 system-ui,sans-serif;max-width:640px;margin:12vh auto;padding:0 20px;color:#0F1C2E">
<h1 style="font-size:22px">This instance is locked until a password is set</h1>
<p>It is running on a public host, and the console has no user accounts: without a password,
anyone with the link could create identities and decrypt documents.</p>
<p>Set <code>PS26237_AUTH_PASS</code> (and optionally <code>PS26237_AUTH_USER</code>) in your
hosting provider's environment variables, then redeploy.</p>
<p style="color:#52647B">If you really intend an open demo, set <code>PS26237_ALLOW_PUBLIC=1</code> instead.</p>
</body>"""


def install_basic_auth(app) -> bool:
    """Adds the gate. Returns True if it is active."""
    user = os.environ.get("PS26237_AUTH_USER", "ps26237")
    password = os.environ.get("PS26237_AUTH_PASS", "")

    if not password:
        if _managed_host() and os.environ.get("PS26237_ALLOW_PUBLIC") != "1":
            # Fail closed, with an explanation instead of an opaque crash.
            @app.before_request
            def _locked():
                if request.path in PUBLIC_PATHS:
                    return None
                return Response(NEEDS_PASSWORD_PAGE, 503, {"Content-Type": "text/html; charset=utf-8"})

            @app.route("/healthz")
            def _healthz_locked():
                return "locked: set PS26237_AUTH_PASS", 200

            app.logger.error("PS26237_AUTH_PASS not set on a public host: all pages locked (503)")
            return False
        app.logger.warning("basic auth disabled (no PS26237_AUTH_PASS set; local use)")
        return False

    @app.before_request
    def _require_auth():
        if request.path in PUBLIC_PATHS:
            return None
        auth = request.authorization
        ok = (auth is not None
              and auth.type == "basic"
              and hmac.compare_digest(auth.username or "", user)
              and hmac.compare_digest(auth.password or "", password))
        if ok:
            return None
        return Response(
            "Authentication required.", 401,
            {"WWW-Authenticate": f'Basic realm="{REALM}", charset="UTF-8"'},
        )

    @app.route("/healthz")
    def _healthz():
        return "ok", 200

    app.logger.info("basic auth enabled for user %r", user)
    return True
