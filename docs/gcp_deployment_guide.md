# Cyber Exposure Governance Platform (CEGP)
### Future Scope — Deploying the Application on Google Cloud Platform (GCP)

> A complete, step-by-step guide to take CEGP from a local Streamlit app to a **secure, internet-accessible, authenticated web service** running on Google Cloud — so a whole team (or auditors) can use it from anywhere, with no one able to reach it without logging in.

**Authors:** Dwaipayan Mojumder · Deblina Das · M.Sc. Cyber Security (4th Sem) · Guidance: Prof. Sanjay Pal

---

## Table of Contents

1. [What We Are Building](#1-what-we-are-building)
2. [Deployment Options Compared](#2-deployment-options-compared)
3. [Prerequisites](#3-prerequisites)
4. [Part 1 — Prepare the App for the Cloud](#part-1--prepare-the-app-for-the-cloud)
5. [Part 2 — Set Up Your GCP Project](#part-2--set-up-your-gcp-project)
6. [Part 3 — Create an Image Repository](#part-3--create-an-image-repository)
7. [Part 4 — Build & Push the Container](#part-4--build--push-the-container)
8. [Part 5 — Deploy to Cloud Run](#part-5--deploy-to-cloud-run)
9. [Part 6 — Protect the Integrity Key with Secret Manager](#part-6--protect-the-integrity-key-with-secret-manager)
10. [Part 7 — Lock It Down with Authentication (IAP)](#part-7--lock-it-down-with-authentication-iap)
11. [Part 8 — Custom Domain & HTTPS](#part-8--custom-domain--https)
12. [Part 9 — Continuous Deployment (Optional)](#part-9--continuous-deployment-optional)
13. [Part 10 — Operate: Logs, Scaling & Updates](#part-10--operate-logs-scaling--updates)
14. [Cost Considerations](#cost-considerations)
15. [Tearing Everything Down](#tearing-everything-down)
16. [Troubleshooting](#troubleshooting)
17. [References](#references)

---

## 1. What We Are Building

We will package CEGP into a **container** (a self-contained, portable bundle of the app and everything it needs), store it in Google's registry, and run it on **Cloud Run** — a fully managed service that runs containers, scales automatically, gives you an HTTPS URL out of the box, and only charges while it is handling requests.

Then we will:
- Store the report-signing key safely in **Secret Manager** (never in code).
- Put **Identity-Aware Proxy (IAP)** in front so that **only people you authorise can reach the app** — everyone else is stopped at a Google login.
- Optionally attach a **custom domain** and set up **automatic re-deployment** when the code changes.

The end result is a professional, secure, always-on deployment.

---

## 2. Deployment Options Compared

GCP offers several ways to host the app. This guide focuses on **Cloud Run**, which is the best fit for a Streamlit application.

| Option | What it is | Best for | This guide |
|---|---|---|---|
| **Cloud Run** | Managed containers, auto-scaling, pay-per-use, HTTPS included | Web apps like this one | ✅ Recommended |
| **App Engine (Flexible)** | Managed app hosting on containers | Similar to Cloud Run, less flexible | Alternative |
| **Compute Engine (VM)** | A virtual machine you manage yourself | Full control, always-on, more upkeep | Alternative |
| **GKE (Kubernetes)** | Container orchestration at scale | Large, complex, multi-service systems | Overkill here |

> **Why Cloud Run?** It needs no servers to manage, scales to zero when idle (so it is cheap), provides a free HTTPS endpoint, and integrates cleanly with Secret Manager and IAP. It also supports the WebSocket connections Streamlit relies on.

---

## 3. Prerequisites

Before starting, make sure you have:

1. **A GCP account with billing enabled.** (You said you already have one.) New accounts include free credits.
2. **The `gcloud` CLI** installed and signed in — the Google Cloud command-line tool. Install from the [Cloud SDK page](https://cloud.google.com/sdk/docs/install), then run `gcloud init`.
3. **The project files** for CEGP on your machine (the folder containing `app.py`, `requirements.txt`, `core/`, `services/`, and `data/`).
4. *(Optional)* **Docker Desktop** if you want to build the container locally. With Cloud Build (used below) you do **not** need Docker installed — Google builds the image for you.

A note on terminology used throughout:
- **Project** — your isolated GCP workspace. Everything lives inside a project, identified by a **Project ID**.
- **Region** — the geographic location your app runs in (e.g. `us-central1`, or `asia-south1` for Mumbai). Pick one close to your users and use it consistently.
- **Container image** — the packaged app, stored in **Artifact Registry**.

Throughout this guide, replace `YOUR_PROJECT_ID` with your actual Project ID and `REGION` with your chosen region.

---

# Part 1 — Prepare the App for the Cloud

A container needs three small files in the project root. None change how the app works locally.

### 1.1 Create a `Dockerfile`

This is the recipe that builds the container. Create a file named `Dockerfile` (no extension) in the project root:

```dockerfile
# Use a small, official Python base image
FROM python:3.12-slim

# Set the working directory inside the container
WORKDIR /app

# Install dependencies first (better build caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Cloud Run provides the port via the PORT environment variable (default 8080)
ENV PORT=8080
EXPOSE 8080

# Start Streamlit, bound to all interfaces on the Cloud Run port
CMD streamlit run app.py \
    --server.port=${PORT} \
    --server.address=0.0.0.0 \
    --server.headless=true \
    --server.enableCORS=false \
    --server.enableXsrfProtection=false
```

> **Why these flags?** Cloud Run injects the port number as `PORT` and expects the app to listen on `0.0.0.0`. `headless=true` stops Streamlit trying to open a browser. Disabling CORS/XSRF avoids WebSocket issues behind Cloud Run's proxy. (Once IAP is in front in Part 7, access is still fully protected.)

### 1.2 Create a `.dockerignore`

This keeps junk and secrets out of the image. Create `.dockerignore` in the project root:

```
.venv/
__pycache__/
*.pyc
.git/
.streamlit/secrets.toml
data/.integrity_key
*.md
```

### 1.3 Confirm `requirements.txt`

Make sure your `requirements.txt` lists everything the app needs. It should contain at least:

```
streamlit>=1.36
pandas>=2.0
plotly>=5.20
requests>=2.31
openpyxl>=3.1.0
xlrd>=2.0.1
```

### 1.4 Read the integrity key from the environment

The app signs reports with `REPORT_INTEGRITY_KEY`. In the cloud, we supply this via Secret Manager (Part 6) rather than a local file — the app already reads this environment variable if present, so no code change is required.

---

# Part 2 — Set Up Your GCP Project

Open a terminal and run these once.

### 2.1 Sign in and pick a project

```bash
gcloud auth login
gcloud config set project YOUR_PROJECT_ID
gcloud config set run/region REGION    # e.g. asia-south1 or us-central1
```

If you need a fresh project:

```bash
gcloud projects create YOUR_PROJECT_ID --name="CEGP"
gcloud config set project YOUR_PROJECT_ID
# Then link a billing account in the Console: Billing > link a billing account
```

### 2.2 Enable the required APIs

These switch on the services we will use:

```bash
gcloud services enable \
  run.googleapis.com \
  artifactregistry.googleapis.com \
  cloudbuild.googleapis.com \
  secretmanager.googleapis.com \
  iap.googleapis.com \
  compute.googleapis.com
```

---

# Part 3 — Create an Image Repository

Artifact Registry is where your container image is stored. Create one repository (once):

```bash
gcloud artifacts repositories create cegp-repo \
  --repository-format=docker \
  --location=REGION \
  --description="CEGP container images"
```

---

# Part 4 — Build & Push the Container

From inside the project folder (where the `Dockerfile` lives), let **Cloud Build** build the image and store it — no local Docker needed:

```bash
gcloud builds submit \
  --tag REGION-docker.pkg.dev/YOUR_PROJECT_ID/cegp-repo/cegp:latest
```

This uploads your code, builds the image in the cloud, and pushes it to Artifact Registry. When it finishes you will see the image path ending in `cegp:latest`.

---

# Part 5 — Deploy to Cloud Run

Now run the image as a live service:

```bash
gcloud run deploy cegp \
  --image REGION-docker.pkg.dev/YOUR_PROJECT_ID/cegp-repo/cegp:latest \
  --region REGION \
  --platform managed \
  --port 8080 \
  --memory 1Gi \
  --cpu 1 \
  --min-instances 0 \
  --max-instances 4 \
  --timeout 3600 \
  --allow-unauthenticated
```

A few notes:
- `--memory 1Gi` is comfortable for pandas/plotly; raise to `2Gi` for very large uploads.
- `--min-instances 0` lets it scale to zero (cheapest); set to `1` to avoid cold-start delay.
- `--timeout 3600` keeps long-lived Streamlit WebSocket sessions alive.
- `--allow-unauthenticated` makes it reachable **for now** so you can confirm it works. **We remove this in Part 7** to lock it down.

When the command finishes it prints a **Service URL** like `https://cegp-xxxxxxxx-uc.a.run.app`. Open it — your app is live on the internet over HTTPS.

> ⚠️ At this point the app is publicly reachable. Do not load real data until you have completed Part 7.

---

# Part 6 — Protect the Integrity Key with Secret Manager

Reports are signed with a secret key. Store it securely instead of in the container.

### 6.1 Create the secret

```bash
# Generate a strong random key and store it as a secret
openssl rand -hex 32 | gcloud secrets create cegp-integrity-key --data-file=-
```

### 6.2 Let Cloud Run read it

Grant the Cloud Run service account access, then attach the secret as an environment variable:

```bash
PROJECT_NUMBER=$(gcloud projects describe YOUR_PROJECT_ID --format='value(projectNumber)')

gcloud secrets add-iam-policy-binding cegp-integrity-key \
  --member="serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"

gcloud run services update cegp \
  --region REGION \
  --update-secrets REPORT_INTEGRITY_KEY=cegp-integrity-key:latest
```

The app will now sign and verify reports using the managed key, and the key never appears in your code or image.

---

# Part 7 — Lock It Down with Authentication (IAP)

This is the most important step: making sure **no one can open the app without signing in** and being authorised. We use **Identity-Aware Proxy (IAP)**, which puts a Google login in front of the app and only lets through users you approve.

There are two supported approaches.

### Approach A (recommended, browser-friendly): External Load Balancer + IAP

IAP for a browser app is applied through an external HTTPS load balancer that points at your Cloud Run service. High-level steps (all available in the Cloud Console under *Network services > Load balancing*, or via `gcloud`):

1. **Make Cloud Run internal-only** so it can only be reached through the load balancer:
   ```bash
   gcloud run services update cegp --region REGION --ingress internal-and-cloud-load-balancing
   ```
2. **Reserve a static external IP** for the load balancer.
3. **Create a Serverless Network Endpoint Group (NEG)** that targets the Cloud Run service.
4. **Create a backend service** and add the serverless NEG to it.
5. **Create a URL map, HTTPS proxy, and forwarding rule** (this is the load balancer front end; attach a Google-managed TLS certificate for HTTPS).
6. **Configure the OAuth consent screen** (*APIs & Services > OAuth consent screen*) — required before IAP can be enabled.
7. **Enable IAP** on the backend service (*Security > Identity-Aware Proxy*), toggle it on for the CEGP backend.
8. **Grant access** to the specific users or Google Groups who may use the app, by giving them the **"IAP-secured Web App User"** role on the resource. Only these identities can pass the login.

After this, visiting the app's address redirects anyone to a Google sign-in; unauthorised accounts are refused. This delivers the SSO-style, "nobody gets in without authentication" behaviour described in the project documentation.

> The full, current command sequence for the load balancer and IAP is long and occasionally changes; follow Google's official walkthrough: **[Enabling IAP for Cloud Run](https://cloud.google.com/iap/docs/enabling-cloud-run)**.

### Approach B (simplest, for tooling/automation): IAM-authenticated Cloud Run

If the app is only consumed by authenticated tools or developers (not casual browsers), you can simply remove public access:

```bash
gcloud run services update cegp --region REGION --no-allow-unauthenticated
```

Then grant the **Cloud Run Invoker** role only to specific users:

```bash
gcloud run services add-iam-policy-binding cegp \
  --region REGION \
  --member="user:someone@example.com" \
  --role="roles/run.invoker"
```

This blocks anonymous access at the IAM layer. For a browser-based dashboard used by a team, **Approach A (IAP) is the better experience**, because it provides a friendly login page rather than requiring identity tokens.

### Role-based access *inside* the app

IAP controls **who can reach** the app. To control **what each person can do** (Viewer / Analyst / Approver / Admin, as described in the project documentation), IAP passes the signed-in user's identity to the app in a request header, which a future version can read to apply in-app roles.

---

# Part 8 — Custom Domain & HTTPS

- **Cloud Run URL:** already HTTPS by default — nothing to do.
- **Your own domain (e.g. `cegp.yourcompany.com`):**
  - With the **load balancer (Approach A)**, point your domain's DNS at the reserved static IP and attach a Google-managed certificate — HTTPS is automatic.
  - Without a load balancer, use Cloud Run **domain mappings** (*Cloud Run > Manage custom domains*) and add the DNS records it shows you.

---

# Part 9 — Continuous Deployment (Optional)

To redeploy automatically whenever you push code to GitHub:

1. Push the project to a GitHub repository.
2. In the Console, open **Cloud Build > Triggers > Create trigger**.
3. Connect your GitHub repo and choose the branch (e.g. `main`).
4. Set the build to use the `Dockerfile` and deploy to Cloud Run (a `cloudbuild.yaml` can define the build-and-deploy steps).

Now every push rebuilds the image and updates the live service with no manual commands.

---

# Part 10 — Operate: Logs, Scaling & Updates

- **View logs:**
  ```bash
  gcloud run services logs read cegp --region REGION
  ```
  or open *Cloud Run > cegp > Logs* in the Console.
- **Redeploy after code changes:** rebuild and deploy again:
  ```bash
  gcloud builds submit --tag REGION-docker.pkg.dev/YOUR_PROJECT_ID/cegp-repo/cegp:latest
  gcloud run deploy cegp --image REGION-docker.pkg.dev/YOUR_PROJECT_ID/cegp-repo/cegp:latest --region REGION
  ```
- **Scaling:** adjust `--min-instances` (responsiveness vs cost) and `--max-instances` (ceiling) on the deploy command.
- **Monitoring & alerts:** use **Cloud Monitoring** to watch request count, latency, and errors, and to set alerts.

> **Note on persistence:** Cloud Run instances are stateless — local files (the audit log, snapshots) reset when an instance restarts. For durable history in production, point the app at a managed database (e.g. **Cloud SQL** or **Firestore**) or write outputs to a **Cloud Storage** bucket. This matches the "database backend" item on the project roadmap.

---

## Cost Considerations

- **Cloud Run** bills per request and per resource-second, and **scales to zero** — when no one is using it, you pay almost nothing. Light, intermittent use typically falls within or near the free tier.
- **Artifact Registry** charges a small amount for stored image size.
- **Secret Manager** is effectively free at this scale.
- **Load Balancer + IAP (Approach A)** has a modest always-on hourly cost for the load balancer — the main cost item in this design. If budget is tight and a friendly login page is not essential, Approach B avoids it.
- Set a **budget alert** (*Billing > Budgets & alerts*) so you are notified before any unexpected spend.

---

## Tearing Everything Down

To remove everything and stop all charges:

```bash
gcloud run services delete cegp --region REGION
gcloud artifacts repositories delete cegp-repo --location REGION
gcloud secrets delete cegp-integrity-key
# Delete any load balancer components and the reserved IP from the Console if you created them.
```

To remove absolutely everything, delete the whole project:

```bash
gcloud projects delete YOUR_PROJECT_ID
```

---

## Troubleshooting

| Symptom | Likely cause & fix |
|---|---|
| **App won't start / "container failed to listen on PORT"** | Streamlit not bound to `0.0.0.0:$PORT`. Confirm the `CMD` flags in the Dockerfile. |
| **Blank page or constant reconnecting** | WebSocket blocked. Ensure `--server.enableCORS=false` and `--server.enableXsrfProtection=false`, and that `--timeout` is high (e.g. 3600). |
| **Slow first load** | Cold start (scaled to zero). Set `--min-instances 1` to keep one warm. |
| **403 / cannot access after IAP** | The user lacks the **IAP-secured Web App User** role; grant it to their account or group. |
| **Build fails on a package** | A dependency is missing from `requirements.txt`, or needs a system library — add it to the Dockerfile with `apt-get install`. |
| **Reports fail to sign** | `REPORT_INTEGRITY_KEY` not attached; re-run the Secret Manager step in Part 6. |

---

## References

- Cloud Run — https://cloud.google.com/run/docs
- Deploying to Cloud Run — https://cloud.google.com/run/docs/deploying
- Artifact Registry — https://cloud.google.com/artifact-registry/docs
- Cloud Build — https://cloud.google.com/build/docs
- Secret Manager — https://cloud.google.com/secret-manager/docs
- Identity-Aware Proxy (IAP) — https://cloud.google.com/iap/docs
- Enabling IAP for Cloud Run — https://cloud.google.com/iap/docs/enabling-cloud-run
- Cloud Run custom domains — https://cloud.google.com/run/docs/mapping-custom-domains
- Cloud SQL — https://cloud.google.com/sql/docs · Firestore — https://cloud.google.com/firestore/docs
- Google Cloud SDK install — https://cloud.google.com/sdk/docs/install

---

*Cyber Exposure Governance Platform — an M.Sc. Cyber Security project by Dwaipayan Mojumder and Deblina Das, under the guidance of Prof. Sanjay Pal.*
