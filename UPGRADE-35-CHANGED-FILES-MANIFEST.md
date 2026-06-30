# Upgrade 35 Changed Files Manifest

Package: `mnb-secure-core-v1.0.1-upgrade-35-changed-files-only.zip`

Upgrade: **35. Token Revocation and Session Control Engine**

This package contains only files changed or added for upgrade 35 and is intended to be applied over the current **MNB Secure Core v1.0.1 upgrade 34** codebase.

## Added

- `src/Token/*`
- `src/Session/*`
- `demos/39-token-revocation-session-control-engine.php`

## Updated

- `src/Core/SecurityKernel.php`
- `src/Security/SecurityConfigValidator.php`
- `src/Vulnerability/VulnerabilityControlMapper.php`
- `src/Pentest/PayloadLibrary.php`
- `src/Pentest/PentestChecklist.php`
- `src/Pentest/VerificationMatrix.php`
- `config/security.php`
- `config/security.production.php`
- `bin/mnb-secure`
- `tests/run-tests.php`
- `README.md`
- `CHANGELOG.md`
- `docs/RELEASE-NOTES-v1.0.1.md`

## Validation summary

- PHP lint: passed
- Tests: 386 passed, 0 failed
- Demos: all demos passed
- Config validate: passed
- Token/session CLI commands: passed
- Vulnerability report: passed
- Vulnerability score: 98.76
- Vulnerability grade: A+
