# Environment and Secret Management

**Package:** `mnb/mnb-secure-core`  
**Version line:** `MNB Secure Core v1.0.1`  
**Documentation topic:** 10. Environment and Secret Management

---

## 1. Purpose

The **Environment and Secret Management** strategy in **MNB Secure Core** provides a safe way to load, validate, use, redact, rotate, and scan secrets across a PHP application.

This topic covers secrets such as:

```text
APP_KEY
DATA_KEY
DATA_SEARCH_HASH_KEY
SIGNED_URL_KEY
WEBHOOK_SECRET
CACHE_ENCRYPTION_KEY
BACKUP_ENCRYPTION_KEY
JWT_SECRET
API tokens
Database passwords
SMTP passwords
Cloud provider keys
Private signing keys
```

Unsafe secret handling can create serious production risks:

- committing `.env` files to Git,
- using weak demo keys in production,
- logging raw passwords, tokens, or cookies,
- reusing one key for all cryptographic purposes,
- failing to rotate old secrets,
- exposing secrets in exception traces,
- storing API tokens in plaintext,
- using production secrets in local development,
- missing webhook secrets,
- shipping real secrets inside public Composer packages or ZIP releases.

The MNB Secure Core secret management layer helps avoid these problems with:

- `.env` loading support,
- provider-based secret access,
- secret definitions and inventory checks,
- production-required secret validation,
- purpose-specific key derivation,
- secret rotation reporting,
- redaction for logs/errors/config dumps,
- project secret scanning,
- environment profile validation,
- final production readiness integration.

---

## 2. Main classes

Environment and secret management lives mainly under:

```text
src/Env/
```

Important classes:

```text
src/Env/EnvLoader.php
src/Env/EnvSecretProvider.php
src/Env/ArraySecretProvider.php
src/Env/SecretProviderInterface.php
src/Env/SecretDefinition.php
src/Env/SecretManager.php
src/Env/SecretInventory.php
src/Env/SecretHealthReport.php
src/Env/SecretRedactor.php
src/Env/SecretScanner.php
src/Env/SecretRotationPolicy.php
src/Env/SecretRotationReport.php
src/Env/EnvironmentProfile.php
src/Env/EnvironmentValidator.php
src/Env/KeyDeriver.php
```

Related integrations:

```text
src/Core/SecurityKernel.php
src/Data/KeyRing.php
src/Logging/LogDataProtector.php
src/Errors/ErrorLogSanitizer.php
src/Production/FinalProductionReadinessChecker.php
src/Security/SecurityConfigValidator.php
src/Security/ProductionSecurityChecker.php
config/security.php
config/security.production.php
bin/mnb-secure
```

---

## 3. Composer installation

Install the package:

```bash
composer require mnb/mnb-secure-core
```

Load Composer autoload:

```php
<?php

require __DIR__ . '/vendor/autoload.php';
```

---

## 4. Recommended `.env` usage

For local development, use a project `.env` file outside public web access.

Example:

```env
APP_ENV=local
APP_DEBUG=true
APP_KEY=local-dev-key-change-me-at-least-32-chars
APP_SECRET_SALT=local-dev-salt

DATA_KEY=
DATA_SEARCH_HASH_KEY=
SIGNED_URL_KEY=
WEBHOOK_SECRET=
CACHE_ENCRYPTION_KEY=
BACKUP_ENCRYPTION_KEY=

DB_HOST=127.0.0.1
DB_DATABASE=mnb_app
DB_USERNAME=mnb_user
DB_PASSWORD=local-db-password
```

For production, use server-level environment variables or a managed secret store. Avoid keeping real production secrets in a committed `.env` file.

Production example:

```env
APP_ENV=production
APP_DEBUG=false
APP_FORCE_HTTPS=true
APP_KEY=use-a-random-32-byte-or-longer-production-secret
APP_SECRET_SALT=use-a-random-32-byte-or-longer-salt

DATA_KEY=use-a-random-32-byte-or-longer-data-key
DATA_SEARCH_HASH_KEY=use-a-random-32-byte-or-longer-search-key
SIGNED_URL_KEY=use-a-random-32-byte-or-longer-signed-url-key
WEBHOOK_SECRET=use-a-random-32-byte-or-longer-webhook-secret
CACHE_ENCRYPTION_KEY=use-a-random-32-byte-or-longer-cache-key
BACKUP_ENCRYPTION_KEY=use-a-random-32-byte-or-longer-backup-key
```

Recommended rule:

```text
Local/demo secrets may be weak only outside production.
Production secrets must be long, random, and managed securely.
```

---

## 5. Loading `.env`

MNB Secure Core includes a lightweight `EnvLoader`.

```php
<?php

use Mnb\SecurityCore\Env\EnvLoader;

require __DIR__ . '/vendor/autoload.php';

EnvLoader::load(__DIR__ . '/.env');

$config = require __DIR__ . '/config/security.php';
```

Read a value safely with a default:

```php
$appEnv = EnvLoader::get('APP_ENV', 'local');
$debug = filter_var(EnvLoader::get('APP_DEBUG', false), FILTER_VALIDATE_BOOL);
```

`EnvLoader` is intentionally simple. In larger frameworks, you can still use your framework's native environment loader and then pass the loaded config into `SecurityKernel`.

---

## 6. Basic kernel usage

Create the kernel:

```php
<?php

use Mnb\SecurityCore\Core\SecurityKernel;
use Mnb\SecurityCore\Env\EnvLoader;

require __DIR__ . '/vendor/autoload.php';

EnvLoader::load(__DIR__ . '/.env');

$config = require __DIR__ . '/config/security.php';
$kernel = new SecurityKernel($config);
```

Access the secret manager:

```php
$secrets = $kernel->secretManager();
```

Read a configured secret:

```php
$appKey = $secrets->require('app.key');
$dataKey = $secrets->get('data.key');
$signedUrlKey = $secrets->get('signed_url.key');
```

Use defaults for optional secrets:

```php
$webhookSecret = $secrets->get('webhook.secret', null);
```

---

## 7. Recommended `secrets` configuration

In `config/security.php`, keep a central `secrets` block.

```php
'secrets' => [
    'enabled' => true,

    'provider' => [
        'driver' => 'env',
        'prefix' => '',
    ],

    'redaction' => [
        'enabled' => true,
        'replacement' => '[redacted]',
        'show_last' => 0,
        'redact_config_dumps' => true,
        'redact_audit_metadata' => true,
        'redact_error_context' => true,
    ],

    'derivation' => [
        'enabled' => true,
        'master' => 'APP_KEY',
        'salt' => $_ENV['APP_SECRET_SALT'] ?? 'mnb-secure-core',
    ],

    'definitions' => [
        'app.key' => [
            'env' => 'APP_KEY',
            'required' => true,
            'production_required' => true,
            'min_length' => 32,
            'purpose' => 'master application key',
            'rotatable' => true,
            'current_key_id' => $_ENV['APP_KEY_ID'] ?? 'app-v1',
            'created_at' => $_ENV['APP_KEY_CREATED_AT'] ?? null,
        ],

        'data.key' => [
            'env' => 'DATA_KEY',
            'required' => false,
            'derive_from' => 'app.key',
            'min_length' => 32,
            'purpose' => 'data encryption',
            'rotatable' => true,
        ],

        'data.search_hash_key' => [
            'env' => 'DATA_SEARCH_HASH_KEY',
            'required' => false,
            'derive_from' => 'app.key',
            'min_length' => 32,
            'purpose' => 'search hash / blind indexes',
            'rotatable' => true,
        ],

        'signed_url.key' => [
            'env' => 'SIGNED_URL_KEY',
            'required' => false,
            'derive_from' => 'app.key',
            'min_length' => 32,
            'purpose' => 'signed URL HMAC',
            'rotatable' => true,
        ],

        'webhook.secret' => [
            'env' => 'WEBHOOK_SECRET',
            'required' => false,
            'production_required' => false,
            'min_length' => 32,
            'purpose' => 'webhook HMAC verification',
            'rotatable' => true,
        ],

        'cache.encryption_key' => [
            'env' => 'CACHE_ENCRYPTION_KEY',
            'required' => false,
            'derive_from' => 'app.key',
            'min_length' => 32,
            'purpose' => 'sensitive cache encryption',
            'rotatable' => true,
        ],

        'backup.encryption_key' => [
            'env' => 'BACKUP_ENCRYPTION_KEY',
            'required' => false,
            'derive_from' => 'app.key',
            'min_length' => 32,
            'purpose' => 'backup encryption/signing',
            'rotatable' => true,
        ],
    ],

    'rotation' => [
        'warn_after_days' => 180,
        'fail_after_days' => 365,
    ],

    'scanning' => [
        'enabled' => true,
        'entropy' => true,
        'fail_on' => 'high',
        'ignore_paths' => ['vendor/', 'storage/', '.git/', 'node_modules/'],
        'allow_patterns' => ['change-me', 'example', 'test-key', 'your-'],
    ],
],
```

---

## 8. Secret definitions

A secret definition describes where a secret comes from and how it should be validated.

Example:

```php
'jwt.signing_key' => [
    'env' => 'JWT_SIGNING_KEY',
    'required' => true,
    'production_required' => true,
    'min_length' => 32,
    'purpose' => 'JWT signing',
    'rotatable' => true,
    'current_key_id' => $_ENV['JWT_KEY_ID'] ?? 'jwt-v1',
    'created_at' => $_ENV['JWT_KEY_CREATED_AT'] ?? null,
],
```

Supported fields:

| Field | Purpose |
|---|---|
| `env` | Environment variable name |
| `required` | Required in all environments |
| `production_required` | Required in production |
| `min_length` | Minimum allowed length |
| `purpose` | Human-readable usage |
| `rotatable` | Whether the secret should rotate periodically |
| `derive_from` | Derive from another secret if missing |
| `sensitive` | Whether to redact value in reports |
| `current_key_id` | Current key/version identifier |
| `previous_key_ids` | Previous key IDs kept during rotation |
| `created_at` | Creation date used by rotation reports |

---

## 9. Secret providers

### 9.1 Environment provider

The default provider reads from `$_ENV`, `$_SERVER`, or `getenv()`.

```php
use Mnb\SecurityCore\Env\EnvSecretProvider;
use Mnb\SecurityCore\Env\SecretManager;

$provider = new EnvSecretProvider();
$manager = SecretManager::fromConfig($config, $provider);

$appKey = $manager->require('app.key');
```

### 9.2 Prefixed environment provider

Useful when you share a server with multiple applications.

```php
$provider = new EnvSecretProvider('MNB_');
```

Then `app.key` configured as `APP_KEY` reads:

```text
MNB_APP_KEY
```

### 9.3 Array provider for tests

Use `ArraySecretProvider` for tests and controlled examples.

```php
use Mnb\SecurityCore\Env\ArraySecretProvider;

$provider = new ArraySecretProvider([
    'APP_KEY' => str_repeat('a', 40),
    'WEBHOOK_SECRET' => str_repeat('b', 40),
], 'test');

$manager = $kernel->secretManager($provider);
```

### 9.4 Custom provider

You can connect your own vault or cloud secret manager by implementing `SecretProviderInterface`.

```php
use Mnb\SecurityCore\Env\SecretProviderInterface;

final class VaultSecretProvider implements SecretProviderInterface
{
    public function get(string $key, mixed $default = null): mixed
    {
        // Fetch from your vault, cloud secret manager, or encrypted store.
        return $this->vaultClient->read($key) ?? $default;
    }

    public function has(string $key): bool
    {
        return $this->vaultClient->exists($key);
    }

    public function source(): string
    {
        return 'vault';
    }
}
```

Use it with the kernel:

```php
$manager = $kernel->secretManager(new VaultSecretProvider($client));
```

---

## 10. Secret inventory checks

Use inventory checks to detect missing, weak, derived, or stale secrets.

```php
$report = $kernel->secretHealthReport()->toArray();

if (!$report['passed']) {
    // Block production deployment or show admin readiness warning.
}
```

Example output shape:

```json
{
  "passed": false,
  "summary": {
    "total": 7,
    "high": 1,
    "medium": 2
  },
  "items": [
    {
      "name": "app.key",
      "env": "APP_KEY",
      "purpose": "master application key",
      "present": true,
      "required": true,
      "min_length": 32,
      "status": "ok",
      "severity": "info",
      "value": "[redacted]"
    }
  ]
}
```

CLI:

```bash
php bin/mnb-secure secrets:inventory
php bin/mnb-secure secrets:audit
```

Recommended deployment rule:

```text
Do not deploy production if required secrets are missing, weak, or invalid.
```

---

## 11. Environment validation

Environment validation checks whether the app environment is safe.

```php
$environmentReport = $kernel->environmentValidator()->validate();

if (!$environmentReport['passed']) {
    // Fail deployment or return admin-only production readiness warning.
}
```

It checks things like:

```text
APP_ENV is production when needed
APP_DEBUG is false in production
HTTPS is forced in production
required secrets are present
required secrets are strong enough
```

CLI:

```bash
php bin/mnb-secure secrets:env-check
```

Production example failure:

```json
{
  "passed": false,
  "environment": "production",
  "issues": [
    {
      "level": "high",
      "key": "debug_enabled_in_production",
      "message": "APP_DEBUG must be false in production."
    }
  ]
}
```

---

## 12. Key derivation

Sometimes you want separate purpose-specific keys without storing every key manually.

MNB Secure Core supports purpose-specific derivation from a master secret.

```php
$derived = $kernel->keyDeriver()->derive('signed-url-v1', 32);
```

Or through the manager:

```php
$dataKey = $kernel->secretManager()->get('data.key');
$searchHashKey = $kernel->secretManager()->get('data.search_hash_key');
```

If these keys are missing and configured with `derive_from => app.key`, they can be derived from `APP_KEY`.

Recommended practice:

```text
Production systems may use explicit separate keys for critical crypto.
Small apps may derive purpose-specific keys from a strong APP_KEY.
Do not reuse the same raw key manually for encryption, signing, search hashes, and backups.
```

---

## 13. Secret redaction

Never log raw secrets. Use the built-in redactor.

```php
$safe = $kernel->secretRedactor()->redactArray([
    'email' => 'admin@example.com',
    'password' => 'secret-password',
    'api_key' => 'live-api-key-value',
    'headers' => [
        'Authorization' => 'Bearer raw-token-here',
        'Cookie' => 'session=raw-session-id',
    ],
]);
```

Result:

```php
[
    'email' => 'admin@example.com',
    'password' => '[redacted]',
    'api_key' => '[redacted]',
    'headers' => [
        'Authorization' => '[redacted]',
        'Cookie' => '[redacted]',
    ],
]
```

Redact free-form text:

```php
$message = 'Authorization: Bearer abc.def.ghi password=super-secret';
$safeMessage = $kernel->secretRedactor()->redactText($message);
```

This integrates with:

```text
Logging
Audit events
Safe error responses
Pentest evidence
Queue payload redaction
Origin log redaction
Production readiness reports
```

---

## 14. Secret scanning

Secret scanning helps catch accidental hardcoded secrets before release.

CLI:

```bash
php bin/mnb-secure secrets:scan
```

The scanner looks for patterns such as:

```text
private keys
AWS-style access keys
Bearer tokens
generic api_key / secret / password / token assignments
high-entropy strings when enabled
```

Recommended CI command:

```bash
php bin/mnb-secure secrets:scan
php bin/mnb-secure config:validate
php bin/mnb-secure production:readiness
```

Recommended ignored paths:

```text
vendor/
storage/
.git/
node_modules/
```

Do not ignore application source paths where secrets may accidentally be committed.

---

## 15. Secret rotation

Secret rotation is the process of replacing old secrets with new secrets safely.

MNB Secure Core provides a rotation report:

```php
$rotation = $kernel->secretRotationReport()->toArray();
```

CLI:

```bash
php bin/mnb-secure secrets:rotate-plan
```

The report checks:

```text
secret is rotatable
secret creation date exists
secret age in days
rotation due soon
rotation overdue
current key ID
previous key IDs
```

Example metadata:

```env
APP_KEY_ID=app-v2
APP_KEY_CREATED_AT=2026-06-01
DATA_KEY_ID=data-v3
DATA_KEY_CREATED_AT=2026-06-01
```

Recommended rotation strategy:

| Secret type | Suggested rotation |
|---|---:|
| App master key | Planned, careful rotation |
| Data encryption key | Requires key ring / migration plan |
| Search hash key | Requires reindexing plan |
| Signed URL key | Rotate with short overlap |
| Webhook secret | Coordinate with sender/receiver |
| API/JWT signing key | Rotate with key IDs and overlap |
| Backup key | Rotate with backup restore planning |

---

## 16. Key rotation safety notes

Different secrets need different rotation behavior.

### 16.1 Signing keys

For signed URLs, JWTs, and webhooks:

```text
Keep current key for signing.
Keep previous keys for verification during overlap.
Expire old signatures/tokens.
Remove old key after safe window.
```

### 16.2 Encryption keys

For encrypted data:

```text
Do not simply replace the key.
Add new key to key ring.
Encrypt new records with new key.
Decrypt old records with previous key.
Re-encrypt old records through a controlled migration.
```

### 16.3 Search hash keys

For blind indexes/search hashes:

```text
Changing the key changes all hashes.
Plan a reindex job.
Support old and new indexes during migration if required.
```

### 16.4 Webhook secrets

For webhook HMAC secrets:

```text
Coordinate rotation with the external sender.
Accept old and new secrets briefly if supported.
Audit failed signatures after rotation.
```

---

## 17. Data protection integration

The data protection engine uses secrets for encryption and search hashes.

Example:

```php
$dataKey = $kernel->secretManager()->get('data.key');
$searchKey = $kernel->secretManager()->get('data.search_hash_key');
```

Typical usage:

```text
DATA_KEY                 → encrypt sensitive fields
DATA_SEARCH_HASH_KEY     → create blind indexes/search hashes
CACHE_ENCRYPTION_KEY     → encrypt sensitive cache payloads
BACKUP_ENCRYPTION_KEY    → encrypt/sign backups
```

Recommended rule:

```text
Use different purpose-specific keys, or derive purpose-specific keys from a strong APP_KEY.
```

---

## 18. Webhook secret integration

Webhook verification needs a real secret.

Example config:

```php
'webhook' => [
    'enabled' => true,
    'secret' => $_ENV['WEBHOOK_SECRET'] ?? null,
],
```

Read through the secret manager:

```php
$secret = $kernel->secretManager()->get('webhook.secret');
```

Production checklist:

```text
WEBHOOK_SECRET is set.
Secret is at least 32 characters.
Webhook signatures are required.
Failed webhook verification is audited.
Secret is not printed in logs or errors.
```

---

## 19. Signed URL key integration

Signed URLs should use a dedicated signing key.

```php
$key = $kernel->secretManager()->get('signed_url.key');
```

Recommended rules:

```text
Use a long random key.
Keep signed URLs short-lived.
Rotate with overlap if old URLs must remain valid.
Never log full signed URLs when they contain sensitive tokens.
```

---

## 20. Cache and backup secret integration

Sensitive cache payloads and backups should use dedicated keys.

```php
$cacheKey = $kernel->secretManager()->get('cache.encryption_key');
$backupKey = $kernel->secretManager()->get('backup.encryption_key');
```

Recommended rules:

```text
Sensitive cache values should be encrypted.
Backup keys must be protected like production database credentials.
Backup rotation must preserve restore ability.
Never store backup encryption keys in the same public backup archive.
```

---

## 21. Database password handling

Database credentials should come from environment or secret providers.

Bad:

```php
'password' => 'hardcoded-db-password',
```

Good:

```php
'password' => $_ENV['DB_PASSWORD'] ?? '',
```

Better for advanced deployments:

```php
'password' => $kernel->secretManager()->get('database.password'),
```

Add a custom secret definition:

```php
'database.password' => [
    'env' => 'DB_PASSWORD',
    'required' => true,
    'production_required' => true,
    'min_length' => 16,
    'purpose' => 'database password',
    'rotatable' => true,
],
```

---

## 22. CI/CD usage

In CI/CD, never print raw secrets. Configure secrets through your CI secret manager.

Recommended pipeline steps:

```bash
composer install --no-dev --optimize-autoloader
php bin/mnb-secure secrets:scan
php bin/mnb-secure secrets:inventory
php bin/mnb-secure secrets:env-check
php bin/mnb-secure config:validate
php bin/mnb-secure final:gate
```

For test pipelines, use non-production secrets:

```env
APP_ENV=testing
APP_DEBUG=false
APP_KEY=testing-key-with-at-least-32-characters
```

Do not use production secrets in test jobs, pull requests, or public CI logs.

---

## 23. Public Composer package safety

Because this library is installed with:

```bash
composer require mnb/mnb-secure-core
```

public package safety matters.

Never publish:

```text
.env
real config secrets
storage/tokens
storage/backups
storage/audit logs
storage/private files
server credentials
private keys
vendor credentials
```

Recommended release archive exclusions:

```text
.git/
vendor/
.env
storage/cache/*
storage/logs/*
storage/audit/*
storage/backups/*
storage/private/*
storage/quarantine/*
storage/tokens/*
```

Keep only `.gitkeep` placeholders for storage folders.

---

## 24. CLI reference

Secret and environment commands:

```bash
php bin/mnb-secure secrets:inventory
php bin/mnb-secure secrets:audit
php bin/mnb-secure secrets:rotate-plan
php bin/mnb-secure secrets:env-check
php bin/mnb-secure secrets:scan
```

Related production commands:

```bash
php bin/mnb-secure config:validate
php bin/mnb-secure production:check
php bin/mnb-secure production:readiness
php bin/mnb-secure production:env-checklist
php bin/mnb-secure final:gate
```

Recommended before deploy:

```bash
php bin/mnb-secure secrets:scan
php bin/mnb-secure secrets:env-check
php bin/mnb-secure production:readiness
php bin/mnb-secure final:gate
```

---

## 25. Example: fail deployment when secrets are weak

```php
$report = $kernel->secretHealthReport()->toArray();

if (!$report['passed']) {
    throw new RuntimeException('Secret readiness check failed. Review secrets:inventory output.');
}
```

For production only:

```php
$environment = $kernel->environmentValidator()->validate();

if (($environment['environment'] ?? '') === 'production' && !$environment['passed']) {
    throw new RuntimeException('Production environment validation failed.');
}
```

---

## 26. Example: safe config dump

Do not dump raw config arrays.

Bad:

```php
var_dump($config);
```

Good:

```php
$safeConfig = $kernel->secretRedactor()->redactArray($config);
print_r($safeConfig);
```

For JSON output:

```php
header('Content-Type: application/json');
echo json_encode($safeConfig, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
```

Never expose this endpoint publicly. It should be CLI-only or admin-only.

---

## 27. Example: safe exception context

When logging exceptions, redact context first.

```php
try {
    // risky operation
} catch (Throwable $e) {
    $logger->error('Operation failed', $kernel->secretRedactor()->redactArray([
        'exception' => get_class($e),
        'message' => $e->getMessage(),
        'request' => $_POST,
        'headers' => getallheaders(),
    ]));
}
```

The safe error engine also applies redaction, but explicit redaction is useful when your app logs manually.

---

## 28. Example: custom secret definition for SMTP

Add to `config/security.php`:

```php
'smtp.password' => [
    'env' => 'SMTP_PASSWORD',
    'required' => false,
    'production_required' => true,
    'min_length' => 16,
    'purpose' => 'SMTP authentication password',
    'rotatable' => true,
],
```

Use it:

```php
$smtpPassword = $kernel->secretManager()->get('smtp.password');
```

Never include it in mail error responses.

---

## 29. Example: custom secret definition for JWT signing

```php
'jwt.signing_key' => [
    'env' => 'JWT_SIGNING_KEY',
    'required' => true,
    'production_required' => true,
    'min_length' => 32,
    'purpose' => 'JWT signing key',
    'rotatable' => true,
    'current_key_id' => $_ENV['JWT_KEY_ID'] ?? 'jwt-v1',
    'previous_key_ids' => array_filter(explode(',', $_ENV['JWT_PREVIOUS_KEY_IDS'] ?? '')),
    'created_at' => $_ENV['JWT_KEY_CREATED_AT'] ?? null,
],
```

Usage:

```php
$jwtKey = $kernel->secretManager()->require('jwt.signing_key');
```

Rotation rule:

```text
New tokens sign with current key.
Old tokens verify with previous keys until they expire.
```

---

## 30. Testing examples

### 30.1 Secret manager resolves required secret

```php
use Mnb\SecurityCore\Core\SecurityKernel;
use Mnb\SecurityCore\Env\ArraySecretProvider;

$config = require __DIR__ . '/../config/security.php';
$kernel = new SecurityKernel($config);

$manager = $kernel->secretManager(new ArraySecretProvider([
    'APP_KEY' => str_repeat('a', 40),
], 'test'));

assert($manager->require('app.key') === str_repeat('a', 40));
```

### 30.2 Missing required production secret fails

```php
$config['app']['env'] = 'production';
$kernel = new SecurityKernel($config);

$manager = $kernel->secretManager(new ArraySecretProvider([], 'test'));

try {
    $manager->require('app.key');
    assert(false, 'Expected missing secret failure.');
} catch (RuntimeException $e) {
    assert(str_contains($e->getMessage(), 'Required secret'));
}
```

### 30.3 Redactor hides sensitive values

```php
$safe = $kernel->secretRedactor()->redactArray([
    'password' => 'super-secret',
    'token' => 'raw-token-value',
]);

assert($safe['password'] === '[redacted]');
assert($safe['token'] === '[redacted]');
```

### 30.4 Scanner detects hardcoded secret pattern

```php
use Mnb\SecurityCore\Env\SecretScanner;

$scanner = new SecretScanner(['entropy' => true]);
$report = $scanner->report(__DIR__ . '/../src');

assert(isset($report['passed']));
```

---

## 31. Production checklist

Before production, verify:

```text
APP_ENV=production
APP_DEBUG=false
APP_FORCE_HTTPS=true
APP_KEY is set and strong
APP_SECRET_SALT is set and strong
DATA_KEY or derivation is configured
DATA_SEARCH_HASH_KEY or derivation is configured
SIGNED_URL_KEY or derivation is configured
WEBHOOK_SECRET is configured when webhooks are enabled
CACHE_ENCRYPTION_KEY is configured when sensitive cache encryption is enabled
BACKUP_ENCRYPTION_KEY is configured when encrypted backups are enabled
DB_PASSWORD is not hardcoded
SMTP/API/cloud secrets are not hardcoded
secrets:scan passes
secrets:inventory passes
secrets:env-check passes
production:readiness passes or known warnings are accepted
final:gate passes before release
```

---

## 32. Common mistakes

### Mistake 1: committing `.env`

Bad:

```text
.env committed to Git
```

Good:

```text
.env.example committed
.env ignored
real secrets configured on the server
```

### Mistake 2: using short keys

Bad:

```env
APP_KEY=123456
```

Good:

```env
APP_KEY=random-production-secret-with-32-plus-characters
```

### Mistake 3: logging raw request data

Bad:

```php
$logger->info('Request', $_POST);
```

Good:

```php
$logger->info('Request', $kernel->secretRedactor()->redactArray($_POST));
```

### Mistake 4: replacing encryption keys without migration

Bad:

```text
Replace DATA_KEY and deploy immediately.
```

Good:

```text
Add key ID, support old key, re-encrypt data, then retire old key.
```

### Mistake 5: using same key for every purpose manually

Bad:

```text
APP_KEY used directly for encryption, signing, search hashes, backups, and webhooks.
```

Good:

```text
Use dedicated keys or purpose-specific derivation.
```

### Mistake 6: exposing secret reports publicly

Bad:

```text
/secrets/inventory endpoint open to the internet
```

Good:

```text
Run secret reports in CLI, CI/CD, or private admin-only environments.
```

---

## 33. Recommended workflow

For local development:

```bash
cp .env.example .env
php bin/mnb-secure secrets:inventory
php bin/mnb-secure config:validate
```

Before commit:

```bash
php bin/mnb-secure secrets:scan
php tests/run-tests.php
```

Before production deployment:

```bash
php bin/mnb-secure secrets:env-check
php bin/mnb-secure production:readiness
php bin/mnb-secure final:gate
```

After rotation:

```bash
php bin/mnb-secure secrets:rotate-plan
php bin/mnb-secure audit:verify
```

---

## 34. Summary

The Environment and Secret Management strategy ensures that sensitive configuration is handled safely across the full application lifecycle.

It provides:

```text
.env loading
provider-based secret access
secret definitions
required/production-required validation
secret inventory reports
key derivation
rotation reports
safe redaction
secret scanning
environment readiness checks
production release integration
```

Use this engine for every secret used by the application: application keys, encryption keys, signed URL keys, webhook secrets, API tokens, database passwords, cache keys, backup keys, and external provider credentials.
