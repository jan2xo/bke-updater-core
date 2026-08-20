# Universal updater operations cookbook

This repository contains reusable update mechanics only. It does not deploy
services, hold signing keys, access VPS infrastructure, or approve releases.

## Local verification

Install the package with its test extras, run Python compilation, run pytest,
and run git diff --check.

## Recovery

Inspect the transaction state directory. A transaction in REPLACING or
VERIFYING is not success; restore the verified backup and record
ROLLED_BACK. A COMMITTED transaction must have passed the local health check.

## Release and signing

Signing remains an owner-controlled Digital Solutions operation. No private
signing key belongs in this repository.

## Production

Production/VPS deployment, signing, artifact publication, and release approval
are intentionally not applicable here.
