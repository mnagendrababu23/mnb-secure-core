# MNB Secure Core v1.0.1 Install Checklist

Use this checklist before exposing an application that depends on MNB Secure Core.

## 1. Install

```bash
composer require mnb/mnb-secure-core
```

If using the GitHub repository directly before Packagist is configured:

```json
{
  "repositories": [
    {"type": "vcs", "url": "https://github.com/YOUR-ORG/mnb-secure-core"}
  ],
  "require": {
    "mnb/mnb-secure-core": "v1.0.1"
  }
}
```

## 2. Copy production examples

```bash
cp .env.production.example .env
cp config/security.production.php config/security.php
```

Then update every `CHANGE_ME` value.

## 3. Generate the app key

```bash
php bin/mnb-secure key:generate
```

Paste the output into:

```env
APP_KEY=PASTE_GENERATED_KEY_HERE
```

## 4. Configure host and proxy trust

Set only real production hosts:

```env
TRUSTED_HOSTS=example.com,www.example.com
```

If your app runs behind a CDN, load balancer, or reverse proxy, set its IP/CIDR ranges:

```env
TRUSTED_PROXIES=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
```

Do not trust `X-Forwarded-*` headers from arbitrary clients.

## 5. Keep writable storage private

Confirm these paths are not inside the public web root:

```env
STORAGE_PRIVATE_PATH=storage/private
STORAGE_QUARANTINE_PATH=storage/quarantine
CACHE_PATH=storage/cache
LOG_PATH=storage/logs
AUDIT_PATH=storage/audit
BACKUP_PATH=storage/backups
TOKEN_STORE_FILE=storage/tokens/tokens.json
```

## 6. Choose storage drivers

Start safely with file drivers:

```env
CACHE_DRIVER=file
RATE_LIMIT_DRIVER=file
TOKEN_STORE_DRIVER=file
```

Move to Redis/database only after confirming the required extension/service is available.

## 7. Configure upload scanning

For production, prefer composite scanning:

```env
UPLOAD_SCANNER_DRIVER=composite
UPLOAD_SCAN_FAIL_CLOSED=true
UPLOAD_STRICT_PRODUCTION=true
```

Install ClamAV or switch to `heuristic` temporarily while keeping strict upload policies enabled.

## 8. Enable security headers

```env
SECURITY_HEADERS_ENABLED=true
HSTS_ENABLED=true
CSP_ENABLED=true
CSP_NONCE_ENABLED=true
CSP_AUTO_NONCE=true
PERMISSIONS_POLICY_PRESET=strict
```

Use `CSP_REPORT_ONLY=true` only while tuning policies, then switch it off.

## 9. Run diagnostics

```bash
php tests/run-tests.php
php demos/run-all-demos.php
php bin/mnb-secure config:validate
php bin/mnb-secure doctor
php bin/mnb-secure secrets:scan
```

`doctor` should pass before release. It can return a non-zero exit code when real blocking issues exist.

## 10. Issue a first API token

```bash
php bin/mnb-secure bootstrap:first-token demo-admin admin:*,profile.read,uploads.write 86400 --write-demo-user
```

The plain token is shown once. Store it securely and rotate it after creating real admin users.

## 11. Verify middleware order

Recommended order:

```text
Request Trust -> Security Headers -> Rate Policy -> API Token Auth -> Permission Guard
```

See:

```text
examples/framework-integration/
examples/quickstart/
```

## 12. Release safely

Push to a review branch first:

```bash
git checkout -b v1.0.1-public-hardening
git push origin v1.0.1-public-hardening
```

Merge to `main` only after tests, demos, doctor, and review are clean.
