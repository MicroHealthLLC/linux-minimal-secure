# Security policy

`harden-and-audit.sh` runs as root and changes how a host is reached (SSH,
firewall, PAM, the boot loader). A flaw in it can lock an operator out or
weaken a host, so reports are taken seriously.

## Reporting a vulnerability

**Do not open a public issue.** Report it privately through GitHub:
**Security → Report a vulnerability** on this repository (private
vulnerability reporting). Include the distribution and release, the
`harden-and-audit.sh --version` output, what you ran, and what happened.

We acknowledge a report within 3 business days and keep you informed until it
is fixed and released.

## Supported versions

Only the newest release on the `main` release line
(`releases/latest`) receives fixes. Always verify a download against its
`.sha256` file before running it.

## What this repository never contains

- Credentials, keys, tokens or host-specific values. Every secret the script
  needs (the GRUB password) is generated on the host at run time and stays
  there (`/root/grub-superuser-password.txt`, mode 0400).
- Anything a run downloads without a pin: the OpenSSL FIPS provider source and
  the SCAP Security Guide content are verified against SHA-256 / SHA-512
  pins in the script before they are used.

CI scans the full history for secrets (gitleaks) and audits the workflows
(zizmor) on every push and pull request.
