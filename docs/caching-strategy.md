# Caching Strategy

**Package:** `mnb/mnb-secure-core`  
**Version line:** `MNB Secure Core v1.0.1`  
**Documentation topic:** 9. Caching Strategy

---

## 1. Purpose

The caching strategy in **MNB Secure Core** provides a safe, policy-driven way to cache application data without breaking security boundaries.

Caching is useful for performance, but unsafe caching can create serious risks:

- leaking one tenant's data to another tenant,
- leaking one user's private response to another user,
- caching sensitive or highly sensitive data by mistake,
- storing secrets in plaintext cache payloads,
- using predictable or unsafe cache keys,
- keeping stale authorization decisions after role or permission changes,
- causing cache stampedes under traffic spikes,
- serving stale data after update/delete operations,
- storing unsafe serialized objects,
- storing very large values that create memory or disk pressure.

The MNB Secure Core caching engine solves these problems with:

- cache policies,
- data classification,
- tenant/user scoped keys,
- safe key building,
- safe serialization,
- optional encryption,
- maximum value size checks,
- tag-based invalidation,
- cache stampede protection,
- TTL jitter,
- audit events,
- safe default denial for highly sensitive data.

---

## 2. Main classes

The caching engine lives mainly under:

```text
src/Cache/
```

Important classes:

```text
src/Cache/CachePolicy.php
src/Cache/CacheDecision.php
src/Cache/CacheRegistry.php
src/Cache/CacheKeyBuilder.php
src/Cache/SecureCache.php
src/Cache/SafeCacheSerializer.php
src/Cache/TaggedCache.php
src/Cache/CacheInvalidator.php
src/Cache/CacheStampedeGuard.php
src/Cache/FileCache.php
src/Cache/RedisCache.php
src/Cache/DatabaseCache.php
src/Cache/EncryptedCache.php
src/Cache/NullCache.php
src/Contracts/CacheInterface.php
```

Related integrations:

```text
src/Core/SecurityKernel.php
src/Web/CacheControlPolicy.php
src/Logging/SecurityAuditTrail.php
src/Data/KeyRing.php
src/Memory/*
src/Throughput/*
src/Token/*
src/Session/*
```

---

## 3. Composer installation

Install the package:

```bash
composer require mnb/mnb-secure-core
```

Then load Composer autoload:

```php
<?php

require __DIR__ . '/vendor/autoload.php';
```

---

## 4. Recommended cache configuration

In `config/security.php`, the cache configuration should look like this:

```php
'caching' => [
    'enabled' => true,
    'default_driver' => 'file',
    'default_ttl' => 300,
    'key_prefix' => 'mnb',
    'tag_prefix' => 'mnb:tag:',

    'security' => [
        'tenant_scoped_by_default' => true,
        'user_scoped_for_sensitive' => true,
        'deny_highly_sensitive' => true,
        'encrypt_sensitive' => true,
        'max_value_bytes' => 1048576,
        'safe_serialization' => true,
    ],

    'stampede' => [
        'enabled' => true,
        'lock_ttl' => 15,
        'jitter_percent' => 10,
        'stale_while_revalidate' => true,
    ],

    'policies' => [
        'public_config' => [
            'ttl' => 3600,
            'data_class' => 'public',
            'scope' => ['global'],
            'tags' => ['config'],
        ],

        'school_settings' => [
            'ttl' => 600,
            'data_class' => 'internal',
            'scope' => ['tenant'],
            'tags' => ['school'],
        ],

        'student_profile' => [
            'ttl' => 300,
            'data_class' => 'sensitive',
            'scope' => ['tenant', 'user'],
            'encrypt' => true,
            'tags' => ['students'],
        ],

        'authz_decision' => [
            'ttl' => 120,
            'data_class' => 'confidential',
            'scope' => ['tenant', 'user'],
            'tags' => ['authz'],
        ],

        'highly_sensitive_default' => [
            'ttl' => 0,
            'data_class' => 'highly_sensitive',
            'cache' => false,
        ],
    ],
],
```

---

## 5. Data classification

`CachePolicy` supports these data classes:

```text
public
internal
confidential
sensitive
highly_sensitive
```

Recommended usage:

| Data class | Cache? | Encrypt? | Scope |
|---|---:|---:|---|
| `public` | Yes | Usually no | `global` |
| `internal` | Yes | Optional | `tenant` or `global` |
| `confidential` | Yes, short TTL | Recommended | `tenant`, `user` |
| `sensitive` | Yes, short TTL | Yes | `tenant`, `user` |
| `highly_sensitive` | No by default | N/A | N/A |

Examples of **highly sensitive** data that should not be cached by default:

```text
passwords
raw tokens
API secrets
private keys
OTP codes
payment secrets
raw identity documents
full medical/financial records
```

---

## 6. Cache scopes

Cache scope controls who can read a cached value.

Supported common scopes:

```text
global
tenant
school
branch
year
academic_year
user
route
```

Example policy:

```php
'student_profile' => [
    'ttl' => 300,
    'data_class' => 'sensitive',
    'scope' => ['tenant', 'user'],
    'encrypt' => true,
    'tags' => ['students'],
],
```

This means the generated cache key depends on tenant/school and user context. Another user or tenant should not receive the same cached value.

---

## 7. Creating a cache registry manually

```php
<?php

use Mnb\SecurityCore\Cache\CacheRegistry;

$registry = CacheRegistry::fromConfig([
    'caching' => [
        'default_ttl' => 300,
        'security' => [
            'encrypt_sensitive' => true,
            'max_value_bytes' => 1048576,
        ],
        'policies' => [
            'school_settings' => [
                'ttl' => 600,
                'data_class' => 'internal',
                'scope' => ['tenant'],
                'tags' => ['school'],
            ],
        ],
    ],
]);

$policy = $registry->get('school_settings');
```

Usually you should access cache through `SecurityKernel`, but manual construction is useful for tests and framework integrations.

---

## 8. Using SecureCache

A typical usage pattern is:

```php
<?php

$cache = $kernel->secureCache();

$settings = $cache->remember(
    'school_settings',
    [
        'tenant_id' => 10,
        'resource_id' => 'settings',
    ],
    function () use ($repository) {
        return $repository->loadSchoolSettings(10);
    }
);
```

This does four important things:

1. resolves the cache policy,
2. builds a safe scoped key,
3. checks whether caching is allowed,
4. stores the value safely using policy TTL, encryption, serialization, and tags.

---

## 9. Put and get usage

```php
<?php

$cache = $kernel->secureCache();

$cache->put('public_config', [
    'key' => 'homepage',
], [
    'site_name' => 'MNB Tools',
    'theme' => 'light',
]);

$config = $cache->get('public_config', [
    'key' => 'homepage',
], default: []);
```

For tenant-scoped data:

```php
<?php

$cache->put('school_settings', [
    'tenant_id' => $schoolId,
    'key' => 'academic-settings',
], $settings);

$settings = $cache->get('school_settings', [
    'tenant_id' => $schoolId,
    'key' => 'academic-settings',
]);
```

---

## 10. User-scoped sensitive cache

Sensitive user-specific data must include user context.

```php
<?php

$profile = $cache->remember('student_profile', [
    'tenant_id' => $schoolId,
    'user_id' => $studentUserId,
    'resource_id' => $studentId,
], function () use ($studentRepository, $studentId) {
    return $studentRepository->findSafeProfile($studentId);
});
```

If the policy requires user scope and `user_id` is missing, `SecureCache` denies caching and returns the default value for reads.

This prevents a dangerous pattern:

```php
// Bad: sensitive user profile without user scope.
$cache->remember('student_profile', ['tenant_id' => $schoolId], fn () => $profile);
```

---

## 11. Cache decisions

Use `decision()` when you want to check whether caching is allowed before reading/writing.

```php
<?php

$decision = $cache->decision('student_profile', [
    'tenant_id' => $schoolId,
    'user_id' => $studentUserId,
]);

if ($decision->denied()) {
    // Fallback to direct repository call.
    $profile = $repository->findSafeProfile($studentId);
}
```

Common denial reasons:

```text
cache_disabled
highly_sensitive_cache_denied
tenant_scope_missing
user_scope_missing
encryption_keyring_missing
```

---

## 12. Safe cache key building

`CacheKeyBuilder` builds safe keys using:

- key prefix,
- policy name,
- data class,
- scope values,
- resource ID,
- optional logical key,
- context fingerprint.

Example key shape:

```text
mnb:policy:student_profile:class:sensitive:tenant:10:user:45:resource:991:ctx:...
```

Do not build cache keys manually from raw user input.

Bad:

```php
$key = 'profile:' . $_GET['id'];
```

Good:

```php
$cache->get('student_profile', [
    'tenant_id' => $schoolId,
    'user_id' => $userId,
    'resource_id' => $studentId,
]);
```

---

## 13. Safe serialization

`SafeCacheSerializer` avoids unsafe arbitrary PHP object serialization patterns.

Recommended cache values:

```text
arrays
strings
integers
floats
booleans
null
simple DTO arrays
```

Avoid caching:

```text
PDO instances
file handles
closures
raw request objects
raw response objects
large binary documents
objects with dangerous __wakeup / __destruct behavior
```

---

## 14. Encryption for sensitive cache values

Sensitive data should be encrypted before being written to cache.

Policy example:

```php
'student_profile' => [
    'ttl' => 300,
    'data_class' => 'sensitive',
    'scope' => ['tenant', 'user'],
    'encrypt' => true,
],
```

If encryption is required but no key ring is available, `SecureCache` denies the cache operation with:

```text
encryption_keyring_missing
```

This is safer than writing sensitive data in plaintext.

---

## 15. Tag-based invalidation

Cache tags allow related entries to be invalidated together.

```php
<?php

$cache->invalidateTags(['students']);
```

Using `CacheInvalidator`:

```php
<?php

$invalidator = $kernel->cacheInvalidator();

$invalidator->invalidateUserAuthorization($userId);
$invalidator->invalidateTenant($schoolId);
$invalidator->invalidatePolicy('authz_decision');
```

Recommended invalidation points:

| Event | Tags to invalidate |
|---|---|
| User role changed | `authz`, `user:{id}` |
| Permission changed | `authz` |
| School settings updated | `school:{id}`, `tenant:{id}` |
| Student profile updated | `students`, `user:{id}` |
| Tenant disabled | `tenant:{id}` |
| Session revoked | `authz`, `user:{id}` |

---

## 16. Authorization decision caching

Authorization decisions can be cached, but only briefly and only with strict invalidation.

Policy example:

```php
'authz_decision' => [
    'ttl' => 120,
    'data_class' => 'confidential',
    'scope' => ['tenant', 'user'],
    'tags' => ['authz'],
],
```

When user roles/permissions change:

```php
<?php

$kernel->cacheInvalidator()->invalidateUserAuthorization($userId);
$kernel->sessionRevocationService()->revokeUser($userId, 'role_changed');
$kernel->tokenRevocationService()->revokeUserTokens($userId, 'role_changed');
```

This prevents stale authorization results from surviving role changes.

---

## 17. Cache stampede protection

A cache stampede happens when many requests miss the same key at the same time and all regenerate the same expensive value.

`CacheStampedeGuard` provides lock-based protection:

```php
<?php

$value = $kernel->cacheStampedeGuard()->rememberLocked(
    'expensive:report:2026',
    300,
    function () {
        return buildExpensiveReport();
    }
);
```

Recommended use cases:

```text
large reports
public configuration
home page data
expensive aggregation queries
external API provider results
SEO/spam-score provider lookups
```

---

## 18. TTL strategy

Use shorter TTLs for sensitive or fast-changing data.

| Cache data | Suggested TTL |
|---|---:|
| Public app config | 30–60 minutes |
| Tenant settings | 5–10 minutes |
| Authorization decision | 1–2 minutes |
| User profile summary | 1–5 minutes |
| External API provider result | 5–30 minutes |
| Queue metrics | 10–60 seconds |
| Security policy config | 1–5 minutes |
| Highly sensitive data | Do not cache |

Use TTL jitter to avoid synchronized expiry spikes.

---

## 19. Stale data strategy

Some cache values can safely be served stale if the fresh source fails.

Good candidates:

```text
public config
non-sensitive dashboards
read-only summaries
provider availability status
```

Bad candidates:

```text
authorization decisions
session status
token revocation state
account disabled status
payment/security-critical data
```

Use `stale_if_error` only for non-security-critical cache policies.

---

## 20. Driver strategy

MNB Secure Core includes multiple cache driver classes:

```text
FileCache
RedisCache
DatabaseCache
NullCache
EncryptedCache
```

Recommended usage:

| Driver | Best for |
|---|---|
| `file` | shared hosting, demos, small apps |
| `redis` | production, high traffic, distributed apps |
| `database` | apps without Redis but with DB availability |
| `null` | testing, disabled cache mode |
| `encrypted` | wrapper for sensitive values |

For production, Redis is usually best when available. File cache is acceptable for small or shared-hosting deployments, but it should be protected by file permissions and cleanup policy.

---

## 21. File cache safety

If using file cache:

- store files outside public web root,
- restrict file permissions,
- avoid caching huge values,
- use retention cleanup,
- avoid sharing cache directories between unrelated apps,
- do not expose `storage/cache` through the web server.

Recommended path:

```text
storage/cache
```

Never use:

```text
public/cache
public_html/cache
```

---

## 22. Redis cache safety

If using Redis:

- do not expose Redis publicly,
- use password/TLS if supported by your environment,
- use a unique key prefix per application,
- avoid storing plaintext secrets,
- configure max memory policy carefully,
- monitor eviction behavior,
- isolate production/staging/test keys.

Recommended key prefix:

```php
'key_prefix' => 'mnb:prod:secure-core',
```

---

## 23. Caching API responses

API response caching must respect authentication and tenant boundaries.

Public response:

```php
$cache->remember('public_config', [
    'key' => 'api-docs-config',
], fn () => $configService->publicApiConfig());
```

Authenticated response:

```php
$cache->remember('student_profile', [
    'tenant_id' => $schoolId,
    'user_id' => $userId,
    'resource_id' => $studentId,
], fn () => $studentService->safeProfile($studentId));
```

Never cache authenticated responses using only the URL as key.

Bad:

```php
$key = 'GET:' . $_SERVER['REQUEST_URI'];
```

This can leak one user's data to another user.

---

## 24. HTTP cache-control headers

Application cache and HTTP cache are different.

For private/authenticated responses, use:

```http
Cache-Control: no-store, private
```

For public static/config responses, controlled caching is acceptable:

```http
Cache-Control: public, max-age=300
```

Use `CacheControlPolicy` or your framework response helpers to avoid browser/proxy caching of sensitive responses.

---

## 25. Database cache integration

Database query results can be cached, but must follow database governance rules.

Recommended:

```php
<?php

$result = $cache->remember('school_settings', [
    'tenant_id' => $tenantId,
    'resource_id' => 'settings',
], function () use ($secureDb, $context, $policy) {
    return $secureDb->findById($context, $policy, 10);
});
```

Rules:

- never cache raw unrestricted query results,
- use `SecureDatabase` policies first,
- use tenant/user scoped cache keys,
- mask sensitive fields before caching,
- invalidate after update/delete/schema change.

---

## 26. Queue and background job cache usage

Background jobs can use cache for:

```text
idempotency windows
provider result caching
queue metrics
worker heartbeat summaries
expensive export progress
```

Do not cache:

```text
raw job secrets
full queue payloads with tokens
private file contents
unredacted failure traces
```

When jobs affect user permissions, sessions, or tenant state, invalidate related cache tags.

---

## 27. Token/session cache safety

Token and session status should generally use their own revocation/session stores.

If cache is used as an optimization:

- use very short TTL,
- keep revocation store as source of truth,
- invalidate on logout, forced logout, password change, role change,
- never cache raw access/refresh tokens.

Do not cache:

```text
JWT secret
raw refresh token
remember-me plaintext token
session cookie value
password reset token
OTP code
```

---

## 28. Audit behavior

`SecureCache` can record audit events for:

```text
cache.hit
cache.write
cache.forget
cache.denied
```

Audit records should include:

- policy name,
- key fingerprint, not raw key,
- data class,
- encrypted status,
- reason for denial,
- safe context only.

Raw cache values should not be written to audit logs.

---

## 29. Common cache policies

### Public application config

```php
'public_config' => [
    'ttl' => 3600,
    'data_class' => 'public',
    'scope' => ['global'],
    'tags' => ['config'],
],
```

### Tenant settings

```php
'school_settings' => [
    'ttl' => 600,
    'data_class' => 'internal',
    'scope' => ['tenant'],
    'tags' => ['school'],
],
```

### User profile summary

```php
'student_profile' => [
    'ttl' => 300,
    'data_class' => 'sensitive',
    'scope' => ['tenant', 'user'],
    'encrypt' => true,
    'tags' => ['students'],
],
```

### Authorization decisions

```php
'authz_decision' => [
    'ttl' => 120,
    'data_class' => 'confidential',
    'scope' => ['tenant', 'user'],
    'tags' => ['authz'],
],
```

### Disable highly sensitive cache

```php
'highly_sensitive_default' => [
    'ttl' => 0,
    'data_class' => 'highly_sensitive',
    'cache' => false,
],
```

---

## 30. Testing examples

### Test tenant scope missing

```php
<?php

$decision = $cache->decision('school_settings', []);

assert($decision->denied());
assert($decision->reason() === 'tenant_scope_missing');
```

### Test sensitive cache requires encryption key ring

```php
<?php

$decision = $cache->decision('student_profile', [
    'tenant_id' => 1,
    'user_id' => 10,
]);

if ($decision->denied()) {
    assert($decision->reason() === 'encryption_keyring_missing');
}
```

### Test highly sensitive denied

```php
<?php

$decision = $cache->decision('highly_sensitive_default', [
    'user_id' => 10,
]);

assert($decision->denied());
```

### Test tag invalidation

```php
<?php

$cache->put('school_settings', [
    'tenant_id' => 5,
    'key' => 'settings',
], ['timezone' => 'Asia/Kolkata']);

$count = $cache->invalidateTags(['school:5']);

assert($count >= 0);
```

---

## 31. CLI checks

Run general validation:

```bash
php bin/mnb-secure config:validate
php bin/mnb-secure doctor
```

Run demos:

```bash
php demos/run-all-demos.php
```

Run tests:

```bash
php tests/run-tests.php
```

If your build exposes cache-specific commands, useful checks are:

```bash
php bin/mnb-secure cache:policy
php bin/mnb-secure cache:check
php bin/mnb-secure cache:invalidate policy authz_decision
```

If cache-specific CLI commands are not enabled in your build, validate caching through tests/demos and `config:validate`.

---

## 32. Production checklist

Before production, verify:

```text
[ ] Cache directory is outside public web root.
[ ] Redis/database cache is not publicly exposed.
[ ] Unique key prefix is configured per environment.
[ ] Sensitive cache values require encryption.
[ ] Highly sensitive data is denied by default.
[ ] Tenant/user scoped policies include tenant_id/user_id context.
[ ] Authorization cache TTL is short.
[ ] Role/permission changes invalidate authz cache.
[ ] Session/token changes invalidate user-scoped cache where needed.
[ ] Cache payload max size is enforced.
[ ] Safe serializer is enabled.
[ ] TTL jitter is enabled.
[ ] Stampede guard is used for expensive recomputation.
[ ] Cache audit logs do not include raw values.
[ ] File cache permissions are restricted.
[ ] Cache cleanup/retention is planned.
```

---

## 33. Common mistakes

### Mistake 1: Caching sensitive data globally

Bad:

```php
$cache->put('public_config', ['key' => 'student:' . $id], $studentProfile);
```

Good:

```php
$cache->put('student_profile', [
    'tenant_id' => $tenantId,
    'user_id' => $userId,
    'resource_id' => $id,
], $safeProfile);
```

---

### Mistake 2: Caching raw tokens

Bad:

```php
$cache->put('public_config', ['key' => 'token'], $refreshToken);
```

Good:

```php
// Store token state in token/session revocation stores, not general cache.
$kernel->tokenRevocationService()->revoke($jti, 'logout');
```

---

### Mistake 3: Forgetting invalidation after role change

Bad:

```php
$user->role = 'admin';
$userRepository->save($user);
```

Good:

```php
$userRepository->save($user);

$kernel->cacheInvalidator()->invalidateUserAuthorization($user->id);
$kernel->sessionRevocationService()->revokeUser($user->id, 'role_changed');
$kernel->tokenRevocationService()->revokeUserTokens($user->id, 'role_changed');
```

---

### Mistake 4: Caching full database results before filtering

Bad:

```php
$rows = $pdo->query('SELECT * FROM students')->fetchAll();
$cache->put('school_settings', ['tenant_id' => $tenantId], $rows);
```

Good:

```php
$rows = $secureDb->search($context, $studentPolicy, $safeFilters);
$rows = $resultFilter->filterRows($rows, $fieldProtection, $context);

$cache->put('student_profile', [
    'tenant_id' => $tenantId,
    'user_id' => $userId,
    'resource_id' => $studentId,
], $rows);
```

---

## 34. Recommended application flow

For a secure read path:

```text
Request received
  ↓
Request trust + auth + tenant context resolved
  ↓
Authorization checked
  ↓
Cache policy decision created
  ↓
Cache key built with tenant/user/resource context
  ↓
Cache read attempted
  ↓
Fallback to secure database/service if cache miss
  ↓
Value filtered/masked
  ↓
Value cached if policy allows
  ↓
Safe response returned
```

For a secure update path:

```text
Request received
  ↓
Auth + authorization checked
  ↓
Secure database update performed
  ↓
Related cache tags invalidated
  ↓
Token/session revocation performed if access changed
  ↓
Audit event recorded
  ↓
Safe response returned
```

---

## 35. Summary

The MNB Secure Core caching strategy is designed for secure performance, not just fast storage.

It provides:

```text
policy-based caching
safe cache keys
tenant/user scoped cache isolation
data classification
encryption for sensitive values
highly sensitive cache denial
safe serialization
max value limits
tag-based invalidation
stampede protection
TTL jitter
audit-safe cache events
```

The most important rule is simple:

```text
Never cache data unless the policy, scope, TTL, encryption, and invalidation strategy are clear.
```
