# Update the project inside the learning repository

The prepared `github-upload/security-alert-triage-lab` folder is a clean copy,
with caches, Git metadata, environment files, and generated runs excluded.
It contains curated fictional examples for reviewers. Do not use the prepared
copy as the active development folder; continue editing the original project.

1. Run and review the two scenarios locally. Confirm the repository's intended
   visibility and commit email privacy before publishing an update.
2. Open your existing learning repository on GitHub and navigate to `projects/`.
   Keep its README and the other project folder.
3. Choose Add file > Upload files. In Finder open Documents > ChatGPT > AI Training
   > github-upload and drag the entire `security-alert-triage-lab` folder.
4. Check paths such as `security-alert-triage-lab/triage/analyze.py` and
   `security-alert-triage-lab/examples/suspicious/report.md`. The upload should
   update files at those existing paths rather than nesting another copy.
5. Review changes, then commit with a message such as
   `Complete local triage analysis, reports, and tests`.
6. Keep the project's existing `.gitignore`. Hidden files are intentionally
   omitted from the browser upload copy; no new ignore rules are needed.
7. Open `projects/security-alert-triage-lab/README.md` on GitHub. Follow its
   example-report and walkthrough links to verify the upload.

Expected source folders are `triage`, `tests`, `data`, `docs`, and `examples`.
No `__pycache__`, `.pyc`, `.git`, `.venv`, credentials, or generated `outputs` runs
should appear in the web upload. The existing root learning-journey README and
project link remain valid. No new repository or GitHub Project board is needed.

For a short demonstration, show one suspicious and one context-supported case,
then a temporary missing-input failure. Explain why priority is not an incident
verdict, why approval is not automatic safety, and what source gaps mean. Run
the test suite and show one negative test. Credit AI assistance honestly and be
prepared to explain or change a rule yourself.
