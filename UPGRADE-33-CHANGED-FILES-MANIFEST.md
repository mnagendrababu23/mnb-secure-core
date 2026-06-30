# Upgrade 33 Changed Files Manifest

Package: `mnb-secure-core-v1.0.1-upgrade-33-changed-files-only.zip`

Upgrade: **33. Origin Identity Protection and Exposure Hardening Engine**

This archive contains only changed/new files. Apply it over the current `MNB Secure Core v1.0.1` codebase after upgrade 32.

## Added

- `src/Origin/*`
- `demos/37-origin-identity-protection-exposure-hardening-engine.php`
- `UPGRADE-33-CHANGED-FILES-MANIFEST.md`

## Updated

- `config/security.php`
- `config/security.production.php`
- `src/Core/SecurityKernel.php`
- `src/Security/ServerIdentityHider.php`
- `src/Security/SecurityConfigValidator.php`
- `src/Http/Middleware/ServerIdentityProtectionMiddleware.php`
- `src/Vulnerability/VulnerabilityControlMapper.php`
- `src/Pentest/PayloadLibrary.php`
- `src/Pentest/PentestChecklist.php`
- `src/Pentest/VerificationMatrix.php`
- `bin/mnb-secure`
- `tests/run-tests.php`
- `README.md`
- `CHANGELOG.md`
- `docs/RELEASE-NOTES-v1.0.1.md`

## New CLI commands

```bash
php bin/mnb-secure origin:policy
php bin/mnb-secure origin:check
php bin/mnb-secure origin:exposure-report
php bin/mnb-secure origin:fingerprint
php bin/mnb-secure origin:firewall-plan
php bin/mnb-secure origin:proxy-profile
php bin/mnb-secure origin:proxy-allowlist
php bin/mnb-secure origin:leak-scan
php bin/mnb-secure origin:production-gate
```
