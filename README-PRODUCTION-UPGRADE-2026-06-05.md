# MNB Secure Core Production Upgrade - 2026-06-05

This package fixes the previously noted readiness gaps:

## Fixed README/config mismatches

- Web middleware examples now use `config['app']['trusted_hosts']`, `config['app']['force_https']`, `config['limits']['request_max_bytes']`, and `config['security_headers']`.
- API token examples now use `OpaqueTokenService::validate()` and `RateLimiterInterface::attempt()`.
- CSRF examples now use `verify()`.
- Upload examples now match the real `FileUploadPolicy` and `SecureFileManager` constructors.
- Database examples now use `DatabaseConfig::fromArray()` and `PdoConnectionFactory()->create()`.

## Added missing middleware

- `src/Http/Middleware/SecurityHeadersMiddleware.php`

This wraps `SecurityHeaders` so it can be used inside the existing `MiddlewarePipeline`.

## Added scalable storage options

New classes:

- `src/Cache/RedisCache.php`
- `src/Cache/DatabaseCache.php`
- `src/RateLimit/RedisRateLimiter.php`
- `src/RateLimit/DatabaseRateLimiter.php`
- `src/Auth/Stores/RedisTokenStore.php`
- `src/Auth/Stores/DatabaseTokenStore.php`

New config blocks:

- `cache`
- `rate_limiter`
- `token_store`
- `redis`

Optional SQL schema:

- `database/storage-drivers-schema.sql`

## Improved upload scanning

New scanners:

- `src/Files/HeuristicMalwareScanner.php`
- `src/Files/ClamAvMalwareScanner.php`
- `src/Files/CompositeMalwareScanner.php`

Upload hardening now includes:

- blocked executable extensions
- filename length checks
- null-byte filename checks
- stricter double-extension checks
- extension/MIME pair validation
- PDF signature validation
- image signature validation
- executable-content pattern rejection for text-like files
- configurable scanner driver: `none`, `heuristic`, `clamav`, or `composite`

## Updated kernel helpers

`SecurityKernel` now provides:

```php
$security->cache();
$security->rateLimiter();
$security->tokenStore();
$security->malwareScanner();
```

Existing helpers like `fileCache()`, `fileRateLimiter()`, `secureFileManager()`, `memoryGuard()`, and `serverIdentityHider()` remain available.

## Validation

- PHP lint passed for all PHP files.
- Test suite passed: 65 passed, 0 failed.
