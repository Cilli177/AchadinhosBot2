# Security policy

## Sensitive material

Do not commit credentials, access tokens, webhook secrets, password hashes, private keys,
session files, QR images, runtime databases, backups, or production exports. Local
configuration belongs in ignored `.env` files; only redacted `*.example` templates may be
versioned.

If sensitive material is found in the repository or its history, stop distribution of the
affected credential, rotate it through the owning service, and record the remediation in a
restricted incident channel. Removing a file from a later commit does not remove it from
history.

## Reporting

Report suspected exposure privately to the repository owner. Do not paste the secret into an
issue, pull request, commit message, log, or chat transcript. Include only the path, commit
identifier, service name, and rotation status.

## Repository checks

Run `scripts/verify-repository-hygiene.ps1` before staging a change. It checks tracked file
names only; it deliberately does not print or inspect environment-file values.
