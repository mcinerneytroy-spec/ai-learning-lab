# Culinary Compass 🌍🍽️

[← AI Learning Lab](../../README.md)

**EXPLORE. TASTE. CONNECT.**

A monthly dinner inspired by a different corner of the world. A shared table.
A new culture. A different menu every month.

**[Open the live website →](https://culinary-compass-1013940445024.us-central1.run.app)** · **[Setup and deployment guide](docs/SETUP.md)**

I built and deployed a dinner-club website where members can vote for dates,
see upcoming meals, and coordinate dishes before signing up. The host chooses
the country, and an email-verified admin manages each episode.

- **Members:** passwordless email sign-in, editable date availability, and a
  shared dish roster. Bringing the same dish as someone else is allowed.
- **Organizer:** country, host, venue, Montana time, final date, cancellation,
  completion, and a confirmed testing reset.
- **Technology:** Python, Streamlit, Google Cloud Run, Firestore, Firebase
  Authentication, and GitHub Actions.
- **What I practiced:** persistent storage, server-side access checks, atomic
  capacity/vote updates, browser session restoration, cloud permissions, and
  deployment through short-lived GitHub-to-Google credentials.

The website is publicly browsable; voting and dish signups require your own
verified email. Published host/venue details are visible to visitors.
Application source remains private; the setup notes below are public.

<details>
<summary><strong>What is needed to build and deploy it?</strong></summary>

1. **GitHub:** an application repository, an authorized source checkout, and
   Actions variables for deployment. Keep credentials and guest data out of Git.
2. **Local tools:** Python 3.12, pip, Git/GitHub Desktop, and Google Cloud CLI.
   Node 24, Java 21, and Firebase CLI are needed for the full local emulator
   suite; Docker is optional because Google can build the image remotely.
3. **Google Cloud:** one project with billing and budget alerts, Cloud Run,
   Cloud Build, Artifact Registry, and separate runtime/build/deployment
   identities with the required permissions.
4. **Firestore:** a Standard / Native mode `(default)` database in the chosen
   region, deny-all browser rules, scheduled backups, and a restore check.
5. **Firebase Authentication:** email-link sign-in, a registered Web app, its
   public configuration, and the actual website hostname authorized for login.
6. **Deployment:** configure the ignored environment file, deploy privately,
   replace the bootstrap URL with the real HTTPS origin, then test public access,
   admin/member separation, votes, and dishes.
7. **GitHub automation:** configure Workload Identity Federation and all nine
   Actions variables using actual values. The current restricted deployment
   workflow uses the existing service and makes it private again; it is not a
   separate staging website.
8. **Maintenance:** monitor costs, retain daily backups for seven days and weekly
   backups for four weeks, and review the explicit 90-day anonymization tool.
   WhatsApp, SMS, and automated event notifications are not configured.

The [complete setup guide](docs/SETUP.md)
includes local commands, cloud configuration, permissions, GitHub variables,
testing checks, and fixes for common installation/deployment errors.

</details>

## About this folder

This folder contains the public project overview and setup documentation. The
running application's Python source is maintained in a separate private
repository; it is not copied into this portfolio folder.
