# Cyber Exposure Governance Platform (CEGP)
### Future Scope — Deploying the Application on Google Cloud Platform (GCP)

> A complete, **beginner-proof**, step-by-step guide to take CEGP from a local Streamlit app to a **secure, internet-accessible, authenticated web service** running on Google Cloud — so a whole team (or auditors) can use it from anywhere, with no one able to reach it without logging in.
>
> This guide assumes **no prior cloud experience**. Every command is explained, every step has a "how to check it worked", and nothing is left as an exercise for the reader.

**Authors:** Dwaipayan Mojumder · Deblina Das · M.Sc. Cyber Security (4th Sem) · Guidance: Prof. Sanjay Pal

---

## How to Use This Guide

- **Follow the parts in order.** Each one builds on the previous.
- **Anything in `monospace`** is either a command you type or a value you replace.
- **`UPPER_CASE` placeholders** (like `YOUR_PROJECT_ID`) must be replaced with your own values. To make this painless, [Step 0.5](#05--set-your-variables-once) sets them once as shell variables so you can copy-paste the rest verbatim.
- **Every step ends with a ✅ "Check it worked" box.** If the check fails, jump to [Troubleshooting](#troubleshooting) before continuing.
- **Boxes marked ⚠️ are important** — read them.

> 💡 **Validated:** The container start-up command, the Streamlit launch flags, the dependency versions, and the integrity-key generation in this guide were test-run before publishing. The health endpoint Cloud Run checks (`/_stcore/health`) returns HTTP 200 with this exact configuration.

---

## A Plain-English Glossary

You do **not** need to memorise these — refer back as needed.

| Term | What it means in one line |
|---|---|
| **Terminal / shell** | The text window where you type commands (Command Prompt / PowerShell on Windows, Terminal on Mac/Linux). |
| **`gcloud`** | Google Cloud's command-line tool — how you control GCP by typing instead of clicking. |
| **Project** | Your isolated workspace on GCP. Everything (services, bills, permissions) lives inside one project, identified by a **Project ID**. |
| **Region** | The physical location your app runs in, e.g. `asia-south1` (Mumbai) or `us-central1` (Iowa). Pick one close to your users and reuse it everywhere. |
| **Container / image** | A self-contained, portable bundle of your app plus everything it needs to run. The bundle is the *image*; a running copy is a *container*. |
| **Dockerfile** | The recipe that tells GCP how to build your image. |
| **Artifact Registry** | Google's storage shelf for your container images. |
| **Cloud Build** | Google's service that builds your image in the cloud (so you don't need Docker on your laptop). |
| **Cloud Run** | The service that *runs* your container, gives it an HTTPS web address, and auto-scales it. |
| **Secret Manager** | A secure vault for passwords and keys, so they never sit in your code. |
| **IAP (Identity-Aware Proxy)** | A Google login gate placed in front of your app — only people you approve can get in. |
| **Service account** | A non-human "robot" identity that GCP services use to talk to each other. |
| **IAM** | Identity and Access Management — GCP's system of *who is allowed to do what*. |

---

## Table of Contents

1. [What We Are Building](#1-what-we-are-building)
2. [Deployment Options Compared](#2-deployment-options-compared)
3. [Part 0 — Get Your Machine Ready (Prerequisites)](#part-0--get-your-machine-ready-prerequisites)
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
14. [Part 11 — Make Data Survive Restarts (Persistence)](#part-11--make-data-survive-restarts-persistence)
15. [Cost Considerations](#cost-considerations)
16. [Security Checklist](#security-checklist)
17. [Tearing Everything Down](#tearing-everything-down)
18. [Troubleshooting](#troubleshooting)
19. [Quick Command Reference (Cheat Sheet)](#quick-command-reference-cheat-sheet)
20. [References](#references)
21. [Appendix — How This Document Is Wired Into the App](#appendix--how-this-document-is-wired-into-the-app)

---

## 1. What We Are Building

We will package CEGP into a **container**, store it in Google's registry, and run it on **Cloud Run** — a fully managed service that runs containers, scales automatically, gives you an HTTPS URL out of the box, and only charges while it is actually handling requests.

Then we will:

- Store the report-signing key safely in **Secret Manager** (never in code).
- Put **Identity-Aware Proxy (IAP)** in front so that **only people you authorise can reach the app** — everyone else is stopped at a Google login.
- Optionally attach a **custom domain** and set up **automatic re-deployment** when the code changes.

**The journey, at a glance:**

```
Your code  ──►  Container image  ──►  Artifact Registry  ──►  Cloud Run (live HTTPS URL)
                                                                     │
                                              Secret Manager (signing key)
                                                                     │
                                                  IAP login gate (authorised users only)
```

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

> **Why Cloud Run?** No servers to manage; it scales to zero when idle (so it is cheap); it provides a free HTTPS endpoint; it integrates cleanly with Secret Manager and IAP; and it supports the WebSocket connections Streamlit relies on.

---

# Part 0 — Get Your Machine Ready (Prerequisites)

Do these one-time setup steps before anything else.

### 0.1 A GCP account with billing enabled

You already have one. If billing is not yet linked: in the [Cloud Console](https://console.cloud.google.com) go to **Billing → Link a billing account**. New accounts include free credits, and this design stays at or near the free tier for light use.

### 0.2 Install the `gcloud` CLI

`gcloud` is the tool you will type all the commands into.

- **Windows:** Download the installer from the [Cloud SDK page](https://cloud.google.com/sdk/docs/install) and run it. When it finishes, tick "Start Google Cloud SDK Shell" — that is your terminal for this guide.
- **macOS / Linux:** Follow the same [install page](https://cloud.google.com/sdk/docs/install); it walks you through a short download-and-extract, then asks you to run `./google-cloud-sdk/install.sh`.

> ✅ **Check it worked** — open a terminal and run:
> ```bash
> gcloud version
> ```
> You should see version numbers (no "command not found"). If it says "command not found", close and reopen the terminal, or re-run the installer.

### 0.3 Open a terminal

- **Windows:** open **Google Cloud SDK Shell** (installed in step 0.2) — recommended, as it is pre-wired for `gcloud`.
- **macOS:** open the **Terminal** app (Applications → Utilities → Terminal).
- **Linux:** open your usual terminal.

### 0.4 Have the project files ready

You need the CEGP project folder on your machine — the folder that contains `app.py`, `requirements.txt`, `core/`, `services/`, and `data/`. In the terminal, move into it:

```bash
cd path/to/your/CEGP-folder
```

> ✅ **Check it worked** — run `ls` (Mac/Linux) or `dir` (Windows). You should see `app.py` in the list.

### 0.5 Set your variables once

To avoid typos later, set these once. **Replace the values** with your own, then paste the block into your terminal. Every later command reuses them.

**macOS / Linux (and the Windows Cloud SDK Shell):**

```bash
export PROJECT_ID="your-project-id"      # e.g. cegp-prod-2026
export REGION="asia-south1"              # e.g. asia-south1 (Mumbai) or us-central1
export SERVICE="cegp"                    # the Cloud Run service name
export REPO="cegp-repo"                  # the Artifact Registry repo name
```

**Windows PowerShell (if you are not using the Cloud SDK Shell):**

```powershell
$PROJECT_ID="your-project-id"
$REGION="asia-south1"
$SERVICE="cegp"
$REPO="cegp-repo"
```

> ⚠️ **Important:** Variables only last for the current terminal window. If you close it, re-paste this block before continuing.
>
> 📝 **Note on examples:** The commands below use the Linux/Mac `$PROJECT_ID` style. On Windows PowerShell, the same variables are written `$PROJECT_ID` too, so the commands work as-is. (In the Cloud SDK Shell on Windows, the Linux style works.)

---

# Part 1 — Prepare the App for the Cloud

A container needs a few small files in the project root. **None of them change how the app runs locally.**

### 1.1 Create a `Dockerfile`

This is the recipe that builds the container. Create a file named exactly `Dockerfile` (no file extension) in the project root, and paste in:

```dockerfile
# Use a small, official Python base image (matches local Python 3.12)
FROM python:3.12-slim

# Keep Python output unbuffered so logs appear immediately in Cloud Run
ENV PYTHONUNBUFFERED=1

# Set the working directory inside the container
WORKDIR /app

# Install dependencies first — this layer is cached, so rebuilds are faster
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application into the image
COPY . .

# Cloud Run tells the app which port to listen on via the PORT variable (default 8080)
ENV PORT=8080
EXPOSE 8080

# Start Streamlit, bound to all network interfaces on the Cloud Run port
CMD streamlit run app.py \
    --server.port=${PORT} \
    --server.address=0.0.0.0 \
    --server.headless=true \
    --server.enableCORS=false \
    --server.enableXsrfProtection=false
```

> **Why these flags?** Cloud Run injects the port number as `PORT` and expects the app to listen on `0.0.0.0` (all interfaces). `headless=true` stops Streamlit trying to open a browser inside the container. Disabling CORS/XSRF avoids WebSocket and file-upload issues behind Cloud Run's proxy. **This is safe** because, after Part 7, IAP is the real security gate in front of the app.

### 1.2 Create a `.dockerignore`

This keeps junk and secrets out of the image (smaller, safer builds). Create `.dockerignore` in the project root:

```
.venv/
venv/
__pycache__/
*.pyc
.git/
.gitignore
.streamlit/secrets.toml
data/.integrity_key
*.md
.DS_Store
```

> **Why exclude `data/.integrity_key`?** The signing key must come from Secret Manager in the cloud (Part 6), never baked into the image.

### 1.3 Pin `requirements.txt`

Make sure your `requirements.txt` lists everything the app needs, **with upper bounds** so a future breaking release cannot silently break your build:

```
streamlit>=1.36,<2.0
pandas>=2.0,<3.0
plotly>=5.20,<7.0
requests>=2.31,<3.0
openpyxl>=3.1.0,<4.0
xlrd>=2.0.1,<3.0
```

> ⚠️ **Audit note:** An unbounded `pandas>=2.0` will install **pandas 3.x**, which has breaking changes versus the 2.x series the app was written against. The `<3.0` cap above prevents that. Apply the same upper-bound discipline to any other library your app imports.

### 1.4 (Recommended) Add a `.streamlit/config.toml`

Putting server settings in a config file is cleaner than long command-line flags and keeps behaviour consistent. Create `.streamlit/config.toml`:

```toml
[server]
headless = true
enableCORS = false
enableXsrfProtection = false

[browser]
gatherUsageStats = false
```

> This is optional — the `Dockerfile` flags already cover it — but it documents intent and helps local runs behave like the cloud.

### 1.5 Read the integrity key from the environment

The app signs reports with `REPORT_INTEGRITY_KEY`. In the cloud we supply this via Secret Manager (Part 6) as an environment variable. The app **already reads this environment variable** if present, so **no code change is required**. (We will confirm this end-to-end in Part 6.)

> ✅ **Check it worked** — your project root now contains: `Dockerfile`, `.dockerignore`, `requirements.txt` (with upper bounds), and optionally `.streamlit/config.toml`. Run `ls -a` (Mac/Linux) or `dir /a` (Windows) to confirm.

---

# Part 2 — Set Up Your GCP Project

Run these once. (Make sure you have set your variables — [Step 0.5](#05--set-your-variables-once).)

### 2.1 Sign in and select your project

```bash
gcloud auth login
gcloud config set project $PROJECT_ID
gcloud config set run/region $REGION
```

`gcloud auth login` opens a browser for you to sign in to your Google account. The other two lines make `gcloud` use your project and region by default.

If you need a **fresh** project instead:

```bash
gcloud projects create $PROJECT_ID --name="CEGP"
gcloud config set project $PROJECT_ID
# Then link a billing account: Console → Billing → Link a billing account
```

> ✅ **Check it worked:**
> ```bash
> gcloud config list
> ```
> Confirm `project = your-project-id` and `region = your-region` are shown.

### 2.2 Enable the required APIs

APIs are the individual GCP services; they are off by default and must be switched on:

```bash
gcloud services enable \
  run.googleapis.com \
  artifactregistry.googleapis.com \
  cloudbuild.googleapis.com \
  secretmanager.googleapis.com \
  iap.googleapis.com \
  compute.googleapis.com
```

This can take a minute or two.

> ✅ **Check it worked:**
> ```bash
> gcloud services list --enabled --filter="config.name:(run.googleapis.com OR iap.googleapis.com)"
> ```
> Both `run.googleapis.com` and `iap.googleapis.com` should appear.

### 2.3 Note your project number (used later)

Some commands need your **project number** (a long digit string, different from the Project ID). Capture it now:

```bash
export PROJECT_NUMBER=$(gcloud projects describe $PROJECT_ID --format='value(projectNumber)')
echo "Project number: $PROJECT_NUMBER"
```

> ✅ **Check it worked** — `echo` prints a long number. If it is blank, re-check `$PROJECT_ID`.

---

# Part 3 — Create an Image Repository

Artifact Registry is the shelf where your container image is stored. Create one repository (once):

```bash
gcloud artifacts repositories create $REPO \
  --repository-format=docker \
  --location=$REGION \
  --description="CEGP container images"
```

> ✅ **Check it worked:**
> ```bash
> gcloud artifacts repositories list --location=$REGION
> ```
> You should see `cegp-repo` (or your `$REPO` name) listed as a `DOCKER` repository.

---

# Part 4 — Build & Push the Container

From inside the project folder (where the `Dockerfile` lives), let **Cloud Build** build the image and store it — **no local Docker needed**:

```bash
gcloud builds submit \
  --tag $REGION-docker.pkg.dev/$PROJECT_ID/$REPO/$SERVICE:latest
```

This uploads your code, builds the image in the cloud, and pushes it to Artifact Registry. The first build takes a few minutes (it downloads the Python base image and installs dependencies). When it finishes you will see the image path ending in `:latest` and a green `SUCCESS`.

> ✅ **Check it worked:**
> ```bash
> gcloud artifacts docker images list \
>   $REGION-docker.pkg.dev/$PROJECT_ID/$REPO
> ```
> Your `cegp` image should be listed with a recent timestamp.

> 🛠️ **If the build fails** on a Python package, a dependency is missing from `requirements.txt`, or it needs a system library. See the [Troubleshooting](#troubleshooting) table.

---

# Part 5 — Deploy to Cloud Run

Now run the image as a live service. **For this first deploy we keep it public** so you can confirm it works; we lock it down in Part 7.

```bash
gcloud run deploy $SERVICE \
  --image $REGION-docker.pkg.dev/$PROJECT_ID/$REPO/$SERVICE:latest \
  --region $REGION \
  --platform managed \
  --port 8080 \
  --memory 1Gi \
  --cpu 1 \
  --cpu-boost \
  --min-instances 0 \
  --max-instances 4 \
  --timeout 3600 \
  --allow-unauthenticated
```

A few notes on the options:

- `--memory 1Gi` is comfortable for pandas/plotly; raise to `2Gi` for very large uploads.
- `--cpu-boost` gives extra CPU during start-up, which noticeably reduces Streamlit's cold-start time.
- `--min-instances 0` lets it scale to zero (cheapest); set to `1` to avoid cold-start delay.
- `--max-instances 4` caps how many copies can run at once (cost ceiling).
- `--timeout 3600` keeps long-lived Streamlit WebSocket sessions alive (max is 3600 seconds = 60 minutes).
- `--allow-unauthenticated` makes it reachable **for now**. **We remove this in Part 7.**

When the command finishes it prints a **Service URL** like `https://cegp-xxxxxxxx-uc.a.run.app`.

> ✅ **Check it worked** — open the printed Service URL in your browser. The CEGP app should load over HTTPS. You can also confirm from the terminal:
> ```bash
> gcloud run services describe $SERVICE --region $REGION --format='value(status.url)'
> curl -s -o /dev/null -w "%{http_code}\n" "$(gcloud run services describe $SERVICE --region $REGION --format='value(status.url)')/_stcore/health"
> ```
> The health check should print `200`.

> ⚠️ **The app is publicly reachable at this point. Do not load real or sensitive data until you have completed Part 7.**

---

# Part 6 — Protect the Integrity Key with Secret Manager

Reports are signed with a secret key. Store it in the vault instead of in the container.

### 6.1 Create the secret

```bash
# Generate a strong random key and store it as a secret named cegp-integrity-key
openssl rand -hex 32 | gcloud secrets create cegp-integrity-key \
  --data-file=- \
  --replication-policy=automatic
```

> `openssl rand -hex 32` produces a 64-character random key. The `|` pipes it straight into the secret, so the key is never written to disk or shown on screen.

> ✅ **Check it worked:**
> ```bash
> gcloud secrets describe cegp-integrity-key --format='value(name)'
> ```
> It prints the secret's full resource name.

### 6.2 Let Cloud Run read it

Grant the Cloud Run runtime service account permission to read the secret, then attach the secret as an environment variable:

```bash
# The default Cloud Run runtime identity is the Compute Engine default service account
gcloud secrets add-iam-policy-binding cegp-integrity-key \
  --member="serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"

# Attach the secret to the service as the REPORT_INTEGRITY_KEY environment variable
gcloud run services update $SERVICE \
  --region $REGION \
  --update-secrets REPORT_INTEGRITY_KEY=cegp-integrity-key:latest
```

The app now signs and verifies reports using the managed key, and the key never appears in your code or image.

> 🔒 **Best-practice upgrade (optional):** For production, create a **dedicated** service account for the service instead of using the default Compute SA, and grant only that account the `secretAccessor` role. This follows least-privilege. For a project deliverable, the default account is acceptable.

> ✅ **Check it worked:**
> ```bash
> gcloud run services describe $SERVICE --region $REGION \
>   --format='value(spec.template.spec.containers[0].env)'
> ```
> You should see `REPORT_INTEGRITY_KEY` referencing the secret. Then reload the app and generate/verify a report — signing should succeed.

---

# Part 7 — Lock It Down with Authentication (IAP)

This is the most important step: making sure **no one can open the app without signing in** and being authorised. We use **Identity-Aware Proxy (IAP)**, which puts a Google login in front of the app and only lets through users you approve.

> ✨ **What changed (and why this guide is simpler than older ones):** As of 2025–2026, Google supports enabling **IAP directly on a Cloud Run service** — a single `--iap` flag, **no load balancer required, and no load-balancer cost**. This is now the recommended approach and is what we use below. (The older load-balancer method still exists and is summarised at the end of this part for completeness.)

### 7.1 First-time setup: the OAuth consent screen (Console — once per project)

IAP shows users a Google sign-in / consent screen, which must be configured once. In a personal or student project (one **without** a Google Workspace organisation), the OAuth client **cannot be created from the command line** — so do this first time in the Console:

1. In the Cloud Console, open **APIs & Services → OAuth consent screen** (or **Google Auth Platform → Branding**).
2. Click **Get started**, fill in the **App name** (e.g. "CEGP") and your support email.
3. For **Audience**, choose **External** (this lets you add specific Google accounts as test/allowed users), then **Create**.
4. The simplest path: open **Cloud Run → your `cegp` service → Security tab → Require authentication → select Identity-Aware Proxy (IAP) → Save**. When you enable IAP from the Console the first time, Google **auto-generates the OAuth client for you** and grants IAP permission to invoke the service automatically.

> 💡 **Recommendation:** Enable IAP for the **first time** via the Console (step 4 above) so the OAuth client is auto-created. After that, you can manage everything else — including adding users — from the command line below.

### 7.2 Enable IAP and remove public access (command line)

If you prefer the CLI (after the one-time consent screen exists), enable IAP and stop anonymous access in one update:

```bash
gcloud run services update $SERVICE \
  --region $REGION \
  --no-allow-unauthenticated \
  --iap
```

Then grant the **IAP service agent** permission to invoke your service (so IAP can forward authenticated traffic to it):

```bash
gcloud run services add-iam-policy-binding $SERVICE \
  --region $REGION \
  --member="serviceAccount:service-${PROJECT_NUMBER}@gcp-sa-iap.iam.gserviceaccount.com" \
  --role="roles/run.invoker"
```

> ⚠️ If you see a warning like *"Deploying services with IAP enabled in a project without an organization may require initial setup via the Cloud Console"*, it means the OAuth client does not exist yet — go back and do [Step 7.1](#71-first-time-setup-the-oauth-consent-screen-console--once-per-project) in the Console first, then re-run this command.

> ✅ **Check IAP is on:**
> ```bash
> gcloud run services describe $SERVICE --region $REGION | grep -i "iap"
> ```
> The output should include `Iap Enabled: true`.

### 7.3 Grant access to specific people

By default, **no one** can get in yet — not even you. Grant each authorised user the **IAP-secured Web App User** role (`roles/iap.httpsResourceAccessor`):

```bash
gcloud iap web add-iam-policy-binding \
  --member="user:someone@example.com" \
  --role="roles/iap.httpsResourceAccessor" \
  --region=$REGION \
  --resource-type=cloud-run \
  --service=$SERVICE
```

Repeat for each person (or use `group:team@example.com` for a Google Group). To **see** who currently has access:

```bash
gcloud iap web get-iam-policy \
  --region=$REGION \
  --resource-type=cloud-run \
  --service=$SERVICE
```

To **remove** someone, use the same command with `remove-iam-policy-binding`.

> ✅ **Check it worked** — open the Service URL in a private/incognito browser window. You should be redirected to a **Google sign-in**. Sign in with an **authorised** account → the app loads. Sign in with an **un-authorised** account → access is refused. This is the "nobody gets in without authentication" behaviour described in the project documentation.

### 7.4 Role-based access *inside* the app (future scope)

IAP controls **who can reach** the app. To control **what each person can do** (Viewer / Analyst / Approver / Admin, as described in the project documentation), IAP passes the signed-in user's identity to the app in a request header (`X-Goog-Authenticated-User-Email`). A future version of CEGP can read that header to apply in-app roles without managing its own passwords.

### 7.5 Advanced alternative (load balancer + IAP)

If you ever need a multi-region setup, Cloud Armor (WAF) rules, or central access management across many backends, you can instead front Cloud Run with an **external HTTPS load balancer** and enable IAP on the backend service. This is more complex and incurs an always-on load-balancer cost. It is **not needed** for CEGP. Reference: [Enabling IAP for Cloud Run (load balancer)](https://cloud.google.com/iap/docs/enabling-cloud-run).

---

# Part 8 — Custom Domain & HTTPS

- **Cloud Run URL:** already HTTPS by default — nothing to do.
- **Your own domain (e.g. `cegp.yourcompany.com`):** use Cloud Run **domain mappings**:
  1. In the Console, go to **Cloud Run → Manage custom domains → Add mapping**.
  2. Select the `cegp` service and enter your domain.
  3. Google shows you DNS records (usually a `CNAME`); add them at your domain registrar.
  4. Wait for DNS to propagate — Google then issues and renews a **managed TLS certificate** automatically, so HTTPS just works.

> 📝 Domain mappings availability varies by region. If it is unavailable in your region, either map the domain in a supported region or use the load-balancer approach from [Step 7.5](#75-advanced-alternative-load-balancer--iap), which supports custom domains everywhere.

---

# Part 9 — Continuous Deployment (Optional)

To redeploy automatically whenever you push code to GitHub, so you never run build commands by hand again.

### 9.1 Add a `cloudbuild.yaml`

Create `cloudbuild.yaml` in the project root. It defines build → push → deploy:

```yaml
steps:
  # 1. Build the container image
  - name: gcr.io/cloud-builders/docker
    args:
      - build
      - -t
      - ${_REGION}-docker.pkg.dev/$PROJECT_ID/${_REPO}/${_SERVICE}:$COMMIT_SHA
      - .

  # 2. Push the image to Artifact Registry
  - name: gcr.io/cloud-builders/docker
    args:
      - push
      - ${_REGION}-docker.pkg.dev/$PROJECT_ID/${_REPO}/${_SERVICE}:$COMMIT_SHA

  # 3. Deploy the new image to Cloud Run
  - name: gcr.io/google.com/cloudsdktool/cloud-sdk
    entrypoint: gcloud
    args:
      - run
      - deploy
      - ${_SERVICE}
      - --image=${_REGION}-docker.pkg.dev/$PROJECT_ID/${_REPO}/${_SERVICE}:$COMMIT_SHA
      - --region=${_REGION}
      - --platform=managed

images:
  - ${_REGION}-docker.pkg.dev/$PROJECT_ID/${_REPO}/${_SERVICE}:$COMMIT_SHA

substitutions:
  _REGION: asia-south1
  _REPO: cegp-repo
  _SERVICE: cegp

options:
  logging: CLOUD_LOGGING_ONLY
```

> Change the three `substitutions` values if yours differ. `$COMMIT_SHA` tags each image with the exact Git commit, so you always know what is running.

### 9.2 Create the trigger

1. Push the project to a GitHub repository.
2. In the Console, open **Cloud Build → Triggers → Create trigger**.
3. Connect your GitHub repo and choose the branch (e.g. `main`).
4. Set **Configuration** to **Cloud Build configuration file** and point it at `cloudbuild.yaml`.
5. Save.

> ✅ **Check it worked** — push a small change to `main`, then watch **Cloud Build → History**. A build should start automatically and end in `SUCCESS`, after which the new revision is live. IAP and your secret settings **persist** across deploys.

---

# Part 10 — Operate: Logs, Scaling & Updates

- **View logs:**
  ```bash
  gcloud run services logs read $SERVICE --region $REGION --limit 100
  ```
  or open **Cloud Run → cegp → Logs** in the Console.

- **Redeploy after code changes** (manual, if not using CD):
  ```bash
  gcloud builds submit --tag $REGION-docker.pkg.dev/$PROJECT_ID/$REPO/$SERVICE:latest
  gcloud run deploy $SERVICE --image $REGION-docker.pkg.dev/$PROJECT_ID/$REPO/$SERVICE:latest --region $REGION
  ```

- **Roll back** to a previous version if something breaks:
  ```bash
  gcloud run revisions list --service $SERVICE --region $REGION
  gcloud run services update-traffic $SERVICE --region $REGION --to-revisions REVISION_NAME=100
  ```

- **Scaling:** adjust `--min-instances` (responsiveness vs cost) and `--max-instances` (ceiling) on the deploy command.

- **Monitoring & alerts:** use **Cloud Monitoring** to watch request count, latency, and errors, and to set alerts.

---

# Part 11 — Make Data Survive Restarts (Persistence)

> ⚠️ **Read this if CEGP stores anything it must not lose** (audit log, snapshots, history).

Cloud Run instances are **stateless**: the container's local disk is **wiped every time the instance restarts, scales to zero, or scales out to a new copy**. Whether that matters to CEGP depends entirely on **where the app currently writes its data**. So first decide which case you are in, then follow only that case.

### 11.0 First — which case are you in?

Look at how CEGP reads and writes its audit log, snapshots, and any saved history. Search the code for file paths such as `open(...)`, `to_csv(...)`, `to_json(...)`, `Path("data/...")`, or `sqlite3.connect("...db")`.

| What you find in the code | Your case |
|---|---|
| It writes to a **local path** inside the project (e.g. `data/audit.log`, `data/snapshots/`, a local `*.db` SQLite file) | **Case A — Local disk** → follow [11.A](#11a--case-a-the-app-writes-to-local-disk) |
| It already writes to a **managed backend** (Cloud SQL / a `postgresql://` or `mysql://` connection, a Cloud Storage bucket / `gs://` path, or Firestore) | **Case B — Managed backend** → follow [11.B](#11b--case-b-the-app-already-uses-a-database-or-bucket) |

> 💡 Not sure? If the app saves anything that should still be there after a redeploy and you have **not** set up a database or bucket, assume **Case A**.

---

### 11.A — Case A: the app writes to local disk

**Then this data will be lost on every restart**, and you must move it to a managed backend before relying on the cloud deployment. Pick the option that matches the kind of data:

- **Cloud Storage bucket** — best for files: exported reports, PDF/Excel artifacts, and snapshot dumps.
  ```bash
  # Create a bucket (bucket names are globally unique — prefix with your project)
  gcloud storage buckets create gs://${PROJECT_ID}-cegp-data --location=$REGION

  # Let the Cloud Run service account read/write objects in it
  gcloud storage buckets add-iam-policy-binding gs://${PROJECT_ID}-cegp-data \
    --member="serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
    --role="roles/storage.objectAdmin"
  ```
  Then either (a) change the app to read/write objects via the `google-cloud-storage` client, or (b) **mount the bucket as a volume** so existing file paths keep working unchanged:
  ```bash
  gcloud run services update $SERVICE --region $REGION \
    --add-volume=name=cegp-data,type=cloud-storage,bucket=${PROJECT_ID}-cegp-data \
    --add-volume-mount=volume=cegp-data,mount-path=/app/data
  ```
  > The volume-mount route (b) is the smallest code change — the app still writes to `data/`, but `data/` now lives in the bucket.

- **Cloud SQL (PostgreSQL/MySQL)** — best for the **structured audit trail** you will want to query and report on. This matches the "database backend" item on the project roadmap. Create an instance, then connect the service:
  ```bash
  gcloud run services update $SERVICE --region $REGION \
    --add-cloudsql-instances=$PROJECT_ID:$REGION:cegp-sql \
    --set-env-vars=DB_CONNECTION="..."   # your app's connection string
  ```

- **Firestore** — a serverless NoSQL option, good for simple document-style records with the least setup; no instance to size or run.

> ✅ **Check it worked** — write a record (e.g. add an audit entry), then force a new revision (`gcloud run deploy ...` again, or set `--min-instances 0` and wait for scale-to-zero). Reload the app: the record should **still be there**.

---

### 11.B — Case B: the app already uses a database or bucket

**Then local-disk loss does not apply** — your data already lives outside the container, so it survives restarts. You only need to confirm the cloud service can **reach** that backend and is **authorised** to use it:

1. **Connectivity & credentials are supplied via the service, not the image.** Pass the connection string / credentials as environment variables or secrets at deploy time, never baked into the container:
   ```bash
   gcloud run services update $SERVICE --region $REGION \
     --set-env-vars=DB_CONNECTION="your-connection-string"
   # or, for a secret value:
   gcloud run services update $SERVICE --region $REGION \
     --update-secrets DB_PASSWORD=cegp-db-password:latest
   ```
2. **Grant the Cloud Run service account the right role** on the backend:
   - Cloud Storage → `roles/storage.objectAdmin` (or `objectViewer` if read-only).
   - Firestore → `roles/datastore.user`.
   - Cloud SQL → `roles/cloudsql.client`, and attach the instance with `--add-cloudsql-instances=$PROJECT_ID:$REGION:INSTANCE`.
3. **If the backend is a private/Cloud SQL instance**, use the built-in connector (the `--add-cloudsql-instances` flag above) rather than exposing a public IP.

> ✅ **Check it worked** — open the app and trigger a read **and** a write against the backend. Both should succeed, and the data should appear directly in the database/bucket (verify in the Console).

> Because your data is already external, you can leave `--min-instances 0` (cheapest) without any risk of losing history.

---

> 📝 **For the current project submission:** demonstrating local/in-memory behaviour is fine to show the app working. This section documents the production-grade path for **both** cases so the work is complete and holds up under questioning.

---

## Cost Considerations

- **Cloud Run** bills per request and per resource-second, and **scales to zero** — when no one is using it, you pay almost nothing. Light, intermittent use typically falls within or near the free tier.
- **Artifact Registry** charges a small amount for stored image size; delete old image versions to keep it minimal.
- **Secret Manager** is effectively free at this scale.
- **IAP (direct on Cloud Run)** adds **no extra cost** and **no load balancer** — this is the main reason to prefer it over the older approach.
- **Cloud Build** has a generous free daily tier; CD builds for a project this size are typically free.
- Set a **budget alert** (**Billing → Budgets & alerts**) so you are notified before any unexpected spend.

---

## Security Checklist

Run through this before treating the deployment as "done":

- [ ] `--allow-unauthenticated` has been removed; `Iap Enabled: true` is confirmed.
- [ ] Only intended users/groups appear in `gcloud iap web get-iam-policy`.
- [ ] The integrity key lives **only** in Secret Manager (not in code, not in the image, not in `.streamlit/secrets.toml`).
- [ ] `.dockerignore` excludes `.git/`, secrets, and the local key file.
- [ ] An incognito test with an **un-authorised** account is correctly **refused**.
- [ ] A budget alert is configured.
- [ ] (Production) A dedicated least-privilege service account is used.
- [ ] (Production) Persistent storage is configured (Part 11) so audit data is not lost.

---

## Tearing Everything Down

To remove the app and stop charges:

```bash
gcloud run services delete $SERVICE --region $REGION
gcloud artifacts repositories delete $REPO --location $REGION
gcloud secrets delete cegp-integrity-key
```

To remove **absolutely everything**, delete the whole project (this is irreversible):

```bash
gcloud projects delete $PROJECT_ID
```

> 📝 If you used the advanced load-balancer approach, also delete the load balancer components and the reserved static IP from the Console, or they keep billing.

---

## Troubleshooting

| Symptom | Likely cause & fix |
|---|---|
| **`gcloud: command not found`** | The CLI is not installed or the terminal was opened before install. Reinstall (Part 0.2) and reopen the terminal. |
| **`PERMISSION_DENIED` on a command** | Your account lacks the IAM role for that action, or the relevant API is not enabled. Re-run Part 2.2 and confirm you are the project owner. |
| **Build fails on a Python package** | A dependency is missing from `requirements.txt`, or it needs a system library. Add the package, or add the library to the `Dockerfile` with `RUN apt-get update && apt-get install -y <lib>`. |
| **Build pulls pandas 3.x and the app errors** | `requirements.txt` lacks upper bounds. Use the pinned versions in Part 1.3 (`pandas>=2.0,<3.0`). |
| **App won't start / "container failed to listen on PORT"** | Streamlit not bound to `0.0.0.0:$PORT`. Confirm the `CMD` flags in the `Dockerfile` exactly match Part 1.1. |
| **Blank page or constant reconnecting** | WebSocket blocked. Ensure `--server.enableCORS=false` and `--server.enableXsrfProtection=false`, and that `--timeout` is high (e.g. 3600). |
| **Slow first load** | Cold start (scaled to zero). Add `--cpu-boost` and/or set `--min-instances 1` to keep one warm. |
| **IAP warning: "project without an organization"** | The OAuth client does not exist yet. Enable IAP **once via the Console** (Part 7.1) so it is auto-created, then use the CLI. |
| **403 after enabling IAP — even for you** | The signed-in user lacks `roles/iap.httpsResourceAccessor`. Grant it (Part 7.3). Also confirm the IAP service agent has `run.invoker` (Part 7.2). |
| **Out-of-org user can't sign in** | The OAuth consent screen audience is set to **Internal**. Change it to **External** under OAuth consent screen / Audience. |
| **Reports fail to sign** | `REPORT_INTEGRITY_KEY` not attached, or the service account lacks `secretAccessor`. Re-run Part 6. |
| **Audit log / snapshots disappear** | Cloud Run is stateless. Move storage to Cloud Storage / Cloud SQL / Firestore (Part 11). |

---

## Quick Command Reference (Cheat Sheet)

```bash
# --- Variables (set once per terminal) ---
export PROJECT_ID="your-project-id"
export REGION="asia-south1"
export SERVICE="cegp"
export REPO="cegp-repo"
export PROJECT_NUMBER=$(gcloud projects describe $PROJECT_ID --format='value(projectNumber)')

# --- One-time project setup ---
gcloud auth login
gcloud config set project $PROJECT_ID
gcloud services enable run.googleapis.com artifactregistry.googleapis.com \
  cloudbuild.googleapis.com secretmanager.googleapis.com iap.googleapis.com compute.googleapis.com
gcloud artifacts repositories create $REPO --repository-format=docker --location=$REGION

# --- Build & deploy ---
gcloud builds submit --tag $REGION-docker.pkg.dev/$PROJECT_ID/$REPO/$SERVICE:latest
gcloud run deploy $SERVICE \
  --image $REGION-docker.pkg.dev/$PROJECT_ID/$REPO/$SERVICE:latest \
  --region $REGION --port 8080 --memory 1Gi --cpu 1 --cpu-boost \
  --min-instances 0 --max-instances 4 --timeout 3600 --allow-unauthenticated

# --- Secret ---
openssl rand -hex 32 | gcloud secrets create cegp-integrity-key --data-file=- --replication-policy=automatic
gcloud secrets add-iam-policy-binding cegp-integrity-key \
  --member="serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"
gcloud run services update $SERVICE --region $REGION \
  --update-secrets REPORT_INTEGRITY_KEY=cegp-integrity-key:latest

# --- Lock down with IAP (enable in Console once, then) ---
gcloud run services update $SERVICE --region $REGION --no-allow-unauthenticated --iap
gcloud run services add-iam-policy-binding $SERVICE --region $REGION \
  --member="serviceAccount:service-${PROJECT_NUMBER}@gcp-sa-iap.iam.gserviceaccount.com" \
  --role="roles/run.invoker"
gcloud iap web add-iam-policy-binding \
  --member="user:someone@example.com" --role="roles/iap.httpsResourceAccessor" \
  --region=$REGION --resource-type=cloud-run --service=$SERVICE

# --- Verify ---
gcloud run services describe $SERVICE --region $REGION | grep -i iap
gcloud run services logs read $SERVICE --region $REGION --limit 50
```

---

## References

- Cloud Run — https://cloud.google.com/run/docs
- Deploy a Streamlit service to Cloud Run — https://cloud.google.com/run/docs/quickstarts/build-and-deploy/deploy-python-streamlit-service
- Deploying container images to Cloud Run — https://cloud.google.com/run/docs/deploying
- Artifact Registry — https://cloud.google.com/artifact-registry/docs
- Cloud Build — https://cloud.google.com/build/docs
- Secret Manager — https://cloud.google.com/secret-manager/docs
- **Configure IAP directly on Cloud Run (recommended)** — https://cloud.google.com/run/docs/securing/identity-aware-proxy-cloud-run
- Enabling IAP for Cloud Run via load balancer (advanced) — https://cloud.google.com/iap/docs/enabling-cloud-run
- Cloud Run custom domains — https://cloud.google.com/run/docs/mapping-custom-domains
- Cloud Run min/max instances & cold starts — https://cloud.google.com/run/docs/configuring/min-instances
- Cloud SQL — https://cloud.google.com/sql/docs · Firestore — https://cloud.google.com/firestore/docs · Cloud Storage — https://cloud.google.com/storage/docs
- Google Cloud SDK install — https://cloud.google.com/sdk/docs/install

---

## Appendix — How This Document Is Wired Into the App

This file is opened from the CEGP UI by the **"Future Scope → Implementation using GCP"** button, exactly like the existing project documentation. Place this file in the project's `docs/` folder (e.g. `docs/gcp_deployment_guide.md`); the button reads and renders it with `st.markdown(...)`. No further wiring is needed — replacing this file updates what the button shows.

---

*Cyber Exposure Governance Platform — an M.Sc. Cyber Security project by Dwaipayan Mojumder and Deblina Das, under the guidance of Prof. Sanjay Pal.*
