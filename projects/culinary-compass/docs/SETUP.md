# Culinary Compass: setup and deployment guide

[Open the live website](https://culinary-compass-1013940445024.us-central1.run.app) · [Project overview](../README.md) · [AI Learning Lab](../../../README.md)

Culinary Compass is a Python/Streamlit website for planning a monthly dinner
inspired by a different country. Guests vote for dates and see who is bringing
what. A verified admin manages the country, host, venue, time, and final date.

This is a public guide to the project's setup. **Application source is currently
private.** Running the application yourself requires an authorized source checkout
or your own implementation. You do not need a developer account to visit the
live website; use your own email to participate. Never share an emailed sign-in link.

## What you need

| Item | Why it is needed |
| --- | --- |
| GitHub account and an application repository | Store source code and run automated checks/deployments |
| Google account, one Google Cloud project, and linked billing | Run Cloud Run, builds, Firestore, and backups |
| Firebase added to that same Google Cloud project | Configure email-link authentication and register the Web app |
| Firestore Standard / Native mode database | Persist episodes, availability, and dish signups |
| Python 3.12 and pip | Run the local Streamlit preview and maintenance tools |
| Google Cloud CLI (`gcloud`) | Authenticate, configure permissions, and deploy |
| Git or GitHub Desktop | Download/update an authorized checkout |
| Node 24, Java 21, and Firebase CLI 15.36.0 | Optional locally; used by the full emulator/test workflow |
| Docker | Optional locally; Google Cloud Build can build the supplied Dockerfile remotely |

No custom domain, Gmail/SMTP server, Cloud SQL database, SMS provider, or WhatsApp
subscription is required for the current feature set. Firebase sends login
messages; event reminders and cancellation notifications are not automated.

## 1. Prepare GitHub and run locally

1. Create a repository for the application, or obtain access to the existing
   private repository. Keep application secrets and member data outside Git.
2. Use GitHub Desktop or Git to clone the source into a new local folder. Do not
   clone over an existing working folder.
3. From the application folder, create a Python 3.12 environment:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
streamlit run app.py
```

Open `http://localhost:8501`. Use **Control + C** in Terminal to stop the server.
On Windows, activate the environment with `.venv\Scripts\activate`.

Local preview uses SQLite and temporary visitor identities. Its Organizer can
be unlocked for development. **Do not expose local preview mode publicly.**
Cloud mode uses Firebase identities and Firestore instead. Local test records
are not automatically imported into the cloud database.

The application includes `.gitignore`, `.dockerignore`, and `.gcloudignore`.
Keep virtual environments, SQLite files, real deployment settings, service-account
keys, temporary `gha-creds*.json` files, and personal screenshots out of source
control and deployment uploads. `.env` files are not loaded automatically.

## 2. Create the Google Cloud project and billing controls

1. Open [Google Cloud Console](https://console.cloud.google.com/) and create one
   project. Record its **project ID** and numeric **project number** separately.
2. Link billing. Configure a monthly budget, alert thresholds, and notification
   recipients before deploying resources.
3. Review [budget alerts](https://docs.cloud.google.com/billing/docs/how-to/budgets)
   and any available [Cloud Run spend cap](https://docs.cloud.google.com/billing/docs/how-to/budgets-spend-caps).
   Alerts alone do not stop spending. Service-specific caps do not cover every
   project charge and can make the website unavailable when reached.
4. Use a region such as **`us-central1`** consistently for Cloud Run and Firestore.
   The website's dinner time zone is independently set to **`America/Denver`**,
   following Montana's winter/summer clock changes.
5. Install the [Google Cloud CLI](https://docs.cloud.google.com/sdk/docs/install)
   for your platform. On a Mac, `uname -m` reports `arm64` for Apple silicon or
   `x86_64` for Intel. Extract the downloaded archive before running its installer.
   Accept the appropriate shell profile (normally `~/.zshrc` on a modern Mac),
   then open a new Terminal window and run `gcloud version`.

Set these variables in the same Terminal window, replacing the project placeholder:

```bash
COMPASS_PROJECT='REPLACE_PROJECT_ID'
COMPASS_REGION='us-central1'
COMPASS_SERVICE='culinary-compass'
COMPASS_RUNTIME="culinary-compass-runtime@${COMPASS_PROJECT}.iam.gserviceaccount.com"
gcloud auth login
gcloud config set project "$COMPASS_PROJECT"
gcloud services enable run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com firestore.googleapis.com identitytoolkit.googleapis.com compute.googleapis.com --project "$COMPASS_PROJECT"
```

Run independent commands on separate lines. A trailing backslash joins lines
into one command. Shell variables disappear when the Terminal session closes;
set them again when returning. `gcloud services list --enabled` verifies APIs.

## 3. Set up Firebase Authentication and Firestore

1. Open [Firebase Console](https://console.firebase.google.com/) and add Firebase
   to the **existing** Google Cloud project. Do not create a second project.
   Google Analytics is not required.
2. Create a **Firestore Standard / Native mode** database with ID **`(default)`**.
   Select the intended region carefully: its location cannot be changed later.
   Choose production rules, then publish the supplied `firestore.rules`.
3. Keep browser database access denied. The Python service accesses Firestore
   through IAM and enforces member ownership and admin permissions on the server.
   Do not enable public/test rules to work around a permission error.
4. Under **Authentication → Sign-in method**, enable **Email/Password** and
   **Email link (passwordless sign-in)**, then save. Both switches are required;
   the website itself does not ask members to create a password.
5. Keep Firebase's default email action handler initially. Branding fields are
   optional; a reply-to address would be visible to recipients. Review the
   [email-link instructions](https://firebase.google.com/docs/auth/web/email-link-auth)
   and [email sending limits](https://firebase.google.com/docs/auth/limits).
6. Under **Project settings → General → Your apps**, select the Web icon (`</>`),
   enter an app nickname, and register it. Leave Firebase Hosting unchecked;
   Cloud Run hosts this application.
7. Save `projectId`, `apiKey`, and `authDomain` from its configuration. The Firebase
   Web API key identifies the browser app; it is not a server private key.
   No service-account JSON key needs to be downloaded.

Firestore records are created by the website. Do not manually create sample
collections or accounts in order to start using it.

## 4. Create service accounts and permissions

The website, build process, and GitHub deployer use separate identities.
The Google account doing initial setup must have permission to administer them.

```bash
gcloud iam service-accounts create culinary-compass-runtime --display-name="Culinary Compass runtime" --project "$COMPASS_PROJECT"
gcloud projects add-iam-policy-binding "$COMPASS_PROJECT" --member="serviceAccount:${COMPASS_RUNTIME}" --role=roles/datastore.user
gcloud projects add-iam-policy-binding "$COMPASS_PROJECT" --member="serviceAccount:${COMPASS_RUNTIME}" --role=roles/firebaseauth.viewer
```

Identify the actual build account, then allow it to build the image:

```bash
COMPASS_BUILD_RESOURCE=$(gcloud builds get-default-service-account --project "$COMPASS_PROJECT" --region "$COMPASS_REGION" --format='value(serviceAccountEmail)')
COMPASS_BUILD="${COMPASS_BUILD_RESOURCE##*/}"
gcloud projects add-iam-policy-binding "$COMPASS_PROJECT" --member="serviceAccount:${COMPASS_BUILD}" --role=roles/run.builder
```

For source deployments, the deployer needs Cloud Run Source Developer and Service
Usage Consumer on the project, plus Service Account User on **both the runtime
and selected build accounts**. Runtime permissions alone do not authorize a
GitHub deployment. See Google's [source deployment permissions](https://docs.cloud.google.com/run/docs/deploying-source-code).

If a newly created service account is briefly reported as nonexistent, wait and
retry the failed permission command. Do not recreate it or grant Owner to fix it.

## 5. Configure and deploy Cloud Run

From the application checkout, copy `deploy/cloud-run.env.example.yaml` to
`deploy/cloud-run.env.yaml` **only if the real file does not exist**. Edit the real
file in a text editor. Replace the `REPLACE_...` placeholders with actual values:

```yaml
APP_ENV: production
CULINARY_COMPASS_BACKEND: firestore
CULINARY_COMPASS_AUTH: firebase
GOOGLE_CLOUD_PROJECT: REPLACE_PROJECT_ID
FIREBASE_API_KEY: REPLACE_FIREBASE_WEB_API_KEY
FIREBASE_AUTH_DOMAIN: REPLACE_FIREBASE_AUTH_DOMAIN
CULINARY_COMPASS_APP_URL: https://setup.invalid
CULINARY_COMPASS_ADMIN_EMAILS: REPLACE_ADMIN_EMAIL
FIRESTORE_DATABASE: '(default)'
```

The temporary `https://setup.invalid` value is intentional **only for the first
private deployment**. Do not send sign-in links until it is replaced. Existing
installations should retain their real canonical app URL. The settings file is
ignored by Git and source uploads; Cloud Run receives it separately below.

```bash
gcloud run deploy "$COMPASS_SERVICE" --source . --project "$COMPASS_PROJECT" --region "$COMPASS_REGION" --service-account "$COMPASS_RUNTIME" --env-vars-file=deploy/cloud-run.env.yaml --cpu=1 --memory=512Mi --min-instances=0 --max-instances=1 --concurrency=20 --timeout=900 --no-allow-unauthenticated
```

Google Cloud builds the Dockerfile remotely. Zero minimum instances and one
maximum instance limit resource use, but open Streamlit connections can keep
compute active. Build, image, database, and backup costs also need monitoring.

After deployment:

1. Copy the returned HTTPS service origin into `CULINARY_COMPASS_APP_URL` in the
   ignored YAML file. Do not include `/account` or a query string.
2. Apply the corrected settings:

```bash
gcloud run services update "$COMPASS_SERVICE" --project "$COMPASS_PROJECT" --region "$COMPASS_REGION" --env-vars-file=deploy/cloud-run.env.yaml
```

3. Add the actual hostname, without `https://` or any path, under **Firebase →
   Authentication → Settings → Authorized domains**.
4. Check Cloud Run's newest revision is ready. A private service returning 403
   in an ordinary browser is expected. An authenticated proxy can help inspect it:

```bash
gcloud run services proxy "$COMPASS_SERVICE" --project "$COMPASS_PROJECT" --region "$COMPASS_REGION" --port=8080
```

Visit `http://localhost:8080`. The proxy occupies that Terminal window until
**Control + C** is pressed. Use a separate Terminal window for other commands.
A proxy test does not verify the real HTTPS email-return path.

## 6. Configure GitHub deployment variables and identity

The repository includes automated tests and a manual deployment workflow.
Configure **Workload Identity Federation** so GitHub uses short-lived Google
credentials instead of a stored JSON private key. Follow the official
[Google GitHub authentication setup](https://github.com/google-github-actions/auth#workload-identity-federation-through-a-service-account).

- Create a dedicated deployment service account and give it the deployer roles
  described in step 4, including permission to use the build account.
- Create a Workload Identity pool/provider for GitHub's issuer. Restrict admission
  to the intended numeric repository/owner IDs and `refs/heads/main`.
- Allow that repository's principal to use the deployment service account with
  Workload Identity User.
- If the workflow changes Cloud Run's access policy, it also needs the appropriate
  service-scoped permission, such as Cloud Run Admin on the existing service.
- Create the GitHub **staging** environment if supported on the account's plan;
  configure environment protection where available.

In **Repository → Settings → Secrets and variables → Actions → Variables**, add:

| Variable name | Actual value to enter |
| --- | --- |
| `GOOGLE_CLOUD_PROJECT` | The project's ID, not its display name or project number |
| `GOOGLE_CLOUD_REGION` | `us-central1` if using this guide's region |
| `RUNTIME_SERVICE_ACCOUNT` | The complete runtime service-account email |
| `DEPLOY_SERVICE_ACCOUNT` | The complete deployment service-account email |
| `WORKLOAD_IDENTITY_PROVIDER` | Full `projects/NUMBER/locations/global/workloadIdentityPools/POOL/providers/PROVIDER` resource name |
| `FIREBASE_API_KEY` | Actual `apiKey` from Firebase's registered Web app |
| `FIREBASE_AUTH_DOMAIN` | Actual `authDomain` from that Web app |
| `CULINARY_COMPASS_APP_URL` | Canonical HTTPS website origin |
| `CULINARY_COMPASS_ADMIN_EMAILS` | The email address authorized to administer the website |

**The right column describes where to obtain values; do not paste those
sentences into GitHub.** Enter the actual values without quotes, backticks, or
an equals sign. Shell names such as `COMPASS_RUNTIME` are not the values.
Do not put service-account private keys or member records into these variables.

Open **Actions → Test application and container** and confirm the intended code
revision passed. The suite covers Python behavior, browser token handoff,
Firestore emulator contracts, dependencies, and a container startup check.
Then use **Deploy restricted Google Cloud staging → Run workflow → main**.

**This project's existing workflow targets the same `culinary-compass` service
and restricts public access.** Its name does not mean there is a separate staging
site or database. A truly isolated staging environment needs a separate service
and separated data/settings. The workflow does not itself require the test job
to pass first; check it before running a deployment.

## 7. Open access and test the live website

After configuring the real URL and authorized domain, allow public browsing for
controlled testing. An unshared address is not an access restriction:

```bash
gcloud run services add-iam-policy-binding "$COMPASS_SERVICE" --project "$COMPASS_PROJECT" --region "$COMPASS_REGION" --member=allUsers --role=roles/run.invoker
```

Check all of the following before sharing it widely:

- Signed-out visitors can browse; Organizer is hidden.
- An emailed sign-in link returns to the real website and completes sign-in.
- The admin sees Organizer; a second non-admin account does not.
- Date votes survive refresh and another sign-in; editing replaces one response.
- Confirming a date closes its poll. Country/time details are correct.
- Existing dishes are visible before signup, duplicates are allowed, and members
  can cancel only their own entries.
- Completion/cancellation retains read-only history and leaves other months intact.
- Sign-out removes admin access. Long-open browser sessions restore after reconnect.

There is no custom inactivity logout timer. The browser component periodically
checks and refreshes short-lived tokens and restores them after server reconnects.
Browser data removal, private browsing restrictions, or account revocation can
still require another sign-in. Firebase verifies email ownership; typing the
admin address alone never grants admin access.

The admin-only **Testing tools · restart all dinner data** control deletes all
episodes, votes, and dishes after a checkbox and the exact phrase
`RESET ALL DINNERS`. It preserves authentication accounts and cloud settings.
It is intended for small test datasets, is atomic, and refuses datasets above
450 event/ballot/signup documents without changing them. Do not use it to cancel
one real dinner; use the normal cancellation action.

## 8. Backups, retention, and ongoing costs

- Configure daily Firestore backups retained **7 days**. Add weekly backups
  retained **28 days** for the agreed second layer of protection. Verify existing
  schedules before adding new ones and include backup charges in the budget.
- Follow Google's [backup and restore guide](https://docs.cloud.google.com/firestore/native/docs/backups)
  and test a restore. Database backups do not back up Firebase Authentication
  accounts, GitHub settings, or IAM policies.
- The supplied retention tool previews anonymization of structured personal data
  from closed meals older than **90 days**. Applying it is an explicit admin
  maintenance action; it is not scheduled automatically. Review free-text fields
  and handle authentication account deletion separately.
- Monitor billing, Cloud Run logs, Firestore usage, and retained container images.
  Set Artifact Registry cleanup policies carefully so rollback images remain.
- Admin completion/cancellation changes the site; it does not send WhatsApp, SMS,
  or event notification emails. Those features are not configured.

## Common problems

| Symptom | Next check |
| --- | --- |
| Installer script not found | Extract the SDK archive and run it from the containing folder |
| Nothing happens after typing a command | Check whether Streamlit/proxy is occupying that Terminal; press Control + C or use a new window |
| GitHub says invalid audience | Use the full identity-provider resource name, not the guide's descriptive text |
| GitHub cannot act as a build account | Grant Service Account User on the actual build identity to the deployer |
| Cloud Run says the container did not listen on port 8080 | Read revision logs; check placeholders, database ID, and runtime permissions before changing ports/timeouts |
| 403 after a restricted deployment | Check Cloud Run public access; the restricted workflow intentionally changes it |
| Email returns to the sign-in page | Use the newest link, check authorized domains/real app URL, and enter the same email if prompted on another browser |
| A website change is missing | Refresh the live site and verify the deployed revision; a local edit alone is not a deployment |
