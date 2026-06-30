# MNB Secure Core v1.0.1 — Upgrade 30 Changed Files Only

Upgrade: Safe Error Response and Technical Log Isolation Engine

This patch package contains only new/modified files for upgrade 30. It excludes runtime/generated storage files, logs, cache files, vendor files, and the full project tree.

## Validation

- PHP lint: passed
- Tests: 287 passed, 0 failed
- Demos: all demos passed
- Config validate: passed
- Error CLI commands: passed
- Vulnerability report: passed
- Vulnerability score: 98.47
- Vulnerability grade: A+

## New CLI commands

```bash
php bin/mnb-secure errors:policy
php bin/mnb-secure errors:catalog
php bin/mnb-secure errors:simulate internal
php bin/mnb-secure errors:simulate validation
php bin/mnb-secure errors:simulate security
php bin/mnb-secure errors:fingerprint
php bin/mnb-secure errors:check-production
```
