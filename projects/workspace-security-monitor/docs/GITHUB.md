# Present this project on GitHub

Git tracks versions of your files locally. GitHub stores and displays a remote
copy called a repository. This folder is not yet a Git repository, and nothing
has been uploaded by this project. No GitHub credentials are needed to run it.

## What a reviewer should see

- The root README: the problem, architecture, quickstart, expected outcomes,
  evidence design, and honest limitations.
- `monitor/`: readable collection, control, and reporting code.
- `tests/`: standard-library tests, including real localhost HTTP integration.
- `data/`: fictional source scenarios. The original `users.json` is retained
  as an early learning exercise; the three controls use `data/scenarios/`.
- `examples/`: curated fictional JSON evidence and CSV reports for both days.
- `docs/`: a demo script, evidence guide, and incremental learning notes.

Generated `outputs/` runs are ignored by Git. Publish the deliberately curated
examples, rather than every local run. Examples include encoded response bodies;
they are fictional data, not sanitized copies of production evidence.

Suggested repository name: `security-evidence-monitor`.
Suggested description: "Python evidence collection demo for MFA coverage,
IAM administrator grants, and endpoint EDR coverage using a local mock API."

## Five-minute project walkthrough

1. Explain that this is a personal demonstration using invented identities,
   devices, events, and project IDs, with no connection to company systems.
2. Show the diagram and three explicit policy definitions in the README.
3. Start the mock server, then run `python3 -m monitor.collect --day 1` in a
   second Terminal. Explain baseline access, missing MFA, and the missing agent.
4. Run `python3 -m monitor.collect --day 2`. Show Blair's MFA improvement,
   Casey's administrator grant to Blair, and the VM's stale agent check-in.
5. Open the newly printed `evidence.json` path and `controls.csv`. Point out
   collector identity versus change actor, source/event times versus collection
   times, raw responses, policy versions, and traceable evidence pointers.
6. Stop the mock server and run the collector again. Show a FAILED run with
   NOT_EVALUATED control summaries, rather than an apparent clean result.
7. Run `python3 -m unittest discover -s tests -v` and discuss one boundary test.

Explain the difference between completed execution and passing controls.
Discuss remaining work: independent population completeness, authenticated
collector identity, access/retention protections, durable baseline management,
review dispositions, real source adapters, and deployment/scheduling.
Credit AI-assisted mentoring and implementation honestly when discussing how
you built it; be prepared to explain and modify the policy code yourself.

## Beginner publishing guide: GitHub Desktop on a Mac

This route uses one Terminal command to start local version tracking, then
GitHub Desktop for sign-in, the first commit, and upload. The mock API does not
need to run. Publishing copies files; it does not deploy the Python server.

### 1. Sign in to your personal account

Open [GitHub](https://github.com) in your browser and sign in, or create an
account if needed. Do not create a repository on the website for this route;
GitHub Desktop will create it when you publish.

### 2. Install and connect GitHub Desktop

Download the Mac application from [GitHub Desktop](https://desktop.github.com/).
Open the downloaded ZIP and launch the extracted application. Follow its sign-in
flow for your personal GitHub account. If asked to configure Git, choose your
author name and preferred account-associated or GitHub-provided private email.
Those values identify your commits; they are not API credentials.

### 3. Start local version tracking

In Terminal, run these two lines one at a time:

```sh
cd "$HOME/Documents/ChatGPT/AI Training/workspace-security-monitor"
git init -b main
```

This creates Git's hidden local history folder. It does not upload files.
This instruction assumes the project has not already been initialized; if it
has, skip `git init` and use the existing repository.

### 4. Add the existing folder to Desktop

In GitHub Desktop, choose File > Add Local Repository. Click Choose and select
the existing `workspace-security-monitor` folder under Documents > ChatGPT >
AI Training. Add that repository. Do not select the parent AI Training folder
or create an extra nested project folder.

### 5. Review and make the first commit

Before committing, configure the public author identity you intend to share.
Git commits include an author name and email. On GitHub, open Settings > Emails,
enable email privacy, and copy your GitHub-provided `noreply` address. The website
privacy setting alone does not configure local Git. From the project folder,
run these commands after replacing both placeholder values:

```sh
git config user.name "YOUR_CHOSEN_PUBLIC_NAME"
git config user.email "YOUR_GITHUB_NOREPLY_EMAIL"
```

These settings apply only to this repository. They do not change previous commits.
Use your chosen public name and the exact private address shown by GitHub; do not
use a personal email by accident. Review identity before the first commit.

In Changes, review the selected files: README, `.gitignore`, Python modules,
tests, fictional data, docs, and curated examples. `.venv`, `__pycache__`, and
generated runs under `outputs/` should be absent; `outputs/.gitkeep` is expected.
If other generated files appear, resolve that before committing them.

For Summary, enter `Add security evidence collection demo`. Then use Commit to
main. A commit saves a local version; it is not the upload step.

### 6. Publish to your account

Choose Publish repository. Suggested name:
`security-evidence-monitor`. Use the description above and your
personal account as owner. Keep the code private initially if you want to review
the remote copy before sharing publicly; otherwise select your intended visibility.
Check that choice before clicking the final Publish Repository button.

This creates and uploads the remote repository. You do not need to paste a token
into Terminal for the Desktop sign-in route. Keep passwords and tokens out of
project files and chat messages.

### 7. Verify the website

Use Repository > View on GitHub. Confirm that the README, source, tests, docs,
and fictional example reports are visible. Open the example JSON and CSV links.
A private repository is visible only to authorized users; public visibility
allows others to inspect it without being invited. The repository URL is the
link to share once its visibility matches your intent.

### 8. Publish later changes

After future edits, review Changes in Desktop, enter a descriptive summary,
commit locally, and choose Push origin to upload. The sequence is edit, review,
commit, push. Do not create a new repository each time.

Official Desktop guides: [installation](https://docs.github.com/en/desktop/installing-and-authenticating-to-github-desktop/installing-github-desktop),
[add a local repository](https://docs.github.com/en/desktop/adding-and-cloning-repositories/adding-a-repository-from-your-local-computer-to-github-desktop),
and [publish an existing project](https://docs.github.com/en/desktop/adding-and-cloning-repositories/adding-an-existing-project-to-github-using-github-desktop).

## What public visibility exposes

Public repository contents and committed history can be viewed and copied by
others. That includes any personal information written in source, documentation,
example outputs, or commit metadata. Publishing a folder does not automatically
publish the rest of your computer or its hostname. Local links such as 127.0.0.1
are loopback addresses, not your public IP address.

Project documentation uses `$HOME` rather than an individual user's home path.
Example hostnames are fictional, and collector labels are demonstration values.
Generated outputs and Python caches are ignored by Git. Review the selected
files and commit identity before publishing. Making a repository private later
does not retract copies people have already downloaded or forked.

See [GitHub's commit email guide](https://docs.github.com/en/account-and-profile/how-tos/email-preferences/setting-your-commit-email-address).

## Alternative: publish using Terminal

These are instructions for a future publishing step, not actions performed yet.
If you already have a personal GitHub repository for projects, decide whether
this should be a subfolder there or its own repository before initializing Git.
The commands below assume a new, separate repository for this project.

1. Review the README, source, tests, and examples. Keep real identities, tokens,
   and company evidence out of the public project. Choose whether it will be
   private or public. Decide on a license before inviting reuse; none is selected.
2. From this project folder, initialize and prepare the local first commit:

   ```sh
   git init -b main
   git add README.md .gitignore monitor tests data docs examples
   git diff --cached --stat
   git status
   git commit -m "Build local security evidence collection demonstration"
   ```

   `add` selects files, `commit` records a local version, and neither uploads
   anything. If Git requests author identity, configure your preferred name and
   GitHub-associated email (or GitHub-provided private email) before committing.
3. On GitHub, create an empty repository under your personal account with the
   desired visibility. Because this project already has a README and ignore
   file, do not initialize another README or ignore file on the website.
4. Copy the repository URL shown by GitHub. The following command contains a
   placeholder: replace `YOUR_REPOSITORY_URL` before running it.

   ```sh
   git remote add origin YOUR_REPOSITORY_URL
   git push -u origin main
   ```

   `push` uploads your committed files. Authentication may be requested; never
   put a token in source code or a remote URL shared with others.
5. Open the GitHub repository to verify README links, examples, and tests are
   present. Share that repository URL, optionally with a short screen recording.

GitHub displays the README as the project landing page. It does not run this
local Python server: `127.0.0.1` links refer to the reader's own computer, so
reviewers must run the demo locally to use them. The example reports can be
reviewed without starting anything.

Official references: [repository quickstart](https://docs.github.com/en/repositories/creating-and-managing-repositories/quickstart-for-repositories)
and [README behavior](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-readmes).
