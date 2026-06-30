# Developer Experience Quickstart

This quickstart is for the first 10 minutes after installing MNB Secure Core v1.0.1.

## Files added for production onboarding

```text
.env.production.example
config/security.production.php
docs/INSTALL-CHECKLIST.md
examples/quickstart/bootstrap-first-token.php
```

## Recommended flow

```bash
cp .env.production.example .env
php bin/mnb-secure key:generate
php bin/mnb-secure config:validate
php bin/mnb-secure doctor
php bin/mnb-secure bootstrap:first-token demo-admin admin:*,profile.read,uploads.write 86400 --write-demo-user
```

## Bootstrap first token from PHP

```php
use Mnb\SecurityCore\Quickstart\FirstTokenBootstrapper;

$config = require __DIR__ . '/../../config/security.php';

$report = (new FirstTokenBootstrapper($config, dirname(__DIR__, 2)))->issue([
    'user_id' => 'demo-admin',
    'scopes' => ['admin:*', 'profile.read', 'uploads.write'],
    'ttl_seconds' => 86400,
    'write_demo_user' => true,
]);

print_r($report['token']['authorization_header']);
```

The token is written through the configured token store and audit trail. It is not a fake token.

## Production note

The bootstrap token is only for first access. After your application has real admin/user management, revoke or rotate it.
