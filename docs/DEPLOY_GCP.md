# Deploying PS 26237 to Google Cloud Platform (Cloud Run)

This guide walks you through deploying the PS 26237 prototype on **Google Cloud Run** using the provided `Dockerfile`.

Cloud Run runs the real Python WSGI container (using `gunicorn`), supporting all dynamic Flask routes, real-time cryptographic operations, and basic authentication protection for public hosting.

---

## Prerequisites

1. [Google Cloud SDK (`gcloud`)](https://cloud.google.com/sdk/docs/install) installed and configured:
   ```bash
   gcloud auth login
   gcloud config set project YOUR_PROJECT_ID
   ```
2. Enable required GCP services:
   ```bash
   gcloud services enable run.googleapis.com artifactregistry.googleapis.com cloudbuild.googleapis.com
   ```

---

## 1-Command Deployment

You can build and deploy directly to Cloud Run from source in a single command:

```bash
gcloud run deploy ps26237 \
  --source . \
  --region us-central1 \
  --allow-unauthenticated \
  --port 8080 \
  --memory 1Gi \
  --cpu 1 \
  --timeout 300 \
  --set-env-vars PS26237_AUTH_USER=ps26237,PS26237_AUTH_PASS=YourSecurePassword123!
```

> **Note on Security:**  
> When deployed to Cloud Run, `app/auth.py` requires `PS26237_AUTH_PASS` to be configured unless `PS26237_ALLOW_PUBLIC=1` is explicitly set. This prevents accidental exposure of the prototype's administration interface.

---

## Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `8080` | Port listened to by Gunicorn (Cloud Run sets this automatically). |
| `PS26237_AUTH_USER` | `ps26237` | Basic Auth username. |
| `PS26237_AUTH_PASS` | *(required)* | Basic Auth password for protected public demo access. |
| `PS26237_ALLOW_PUBLIC` | `0` | Set to `1` to run without basic authentication. |
| `PS26237_HOME` | `/tmp/ps26237_workspace` | Workspace path inside container instance. |

---

## Verification

Once deployed, Google Cloud Run will output your Service URL (e.g., `https://ps26237-xyz-uc.a.run.app`).

1. Open `https://<service-url>/healthz` -> returns `200 ok`.
2. Open `https://<service-url>/` in your browser.
3. Authenticate with your username (`ps26237`) and password (`YourSecurePassword123!`).
4. Demo identities (`alice`, `bob`, `carol`) are pre-seeded automatically on first boot.
