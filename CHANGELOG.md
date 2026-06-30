# Changelog

All notable changes to `mnb-secure-core` are documented here.

## v1.0.1 - Public Package Hardening

### Added
- MIT license file for public GitHub/package use.
- GitHub Actions CI workflow for PHP 8.1, 8.2, 8.3, and 8.4.
- `.gitattributes` release hygiene rules to exclude `.git`, CI metadata, and generated storage content from exported archives.
- `SECURITY.md` with responsible disclosure guidance.
- `TRUSTED_PROXIES` configuration for safe reverse-proxy HTTPS detection.

### Changed
- Composer metadata now declares required PHP extensions and removes the inline Composer `version` field so Git tags can be the package source of truth.
- `Request::isSecure()` now trusts `X-Forwarded-Proto` only when the request comes from a configured trusted proxy.
- `ApiTokenMiddleware` now exposes validated token context through request attributes: `auth_token`, `auth_user_id`, and `auth_scopes`.
- Database cache, rate limiter, and token store constructors validate configured SQL table identifiers before interpolating table names into SQL.
- ClamAV scanner now enforces the configured timeout instead of allowing a long-running scanner process to hang indefinitely.
- Redis token store no longer shortens the per-user token index TTL when a shorter-lived token is stored.
- Production checker now warns when production ClamAV/composite upload scanning is configured to fail open.
- Demo 10 now includes origin-protection configuration so the complete demo suite remains green.

### Compatibility
- No namespaces, class names, or existing public methods were removed.
- `Request::fromGlobals()` accepts an optional trusted-proxies array while existing zero-argument usage remains valid.
- `Request` now includes optional `withAttribute()` / `attribute()` helpers for downstream auth context without breaking existing request handling.

### v1.0.1 Release Readiness Pack

- Added GitHub pull request template with compatibility, security, and verification checklist.
- Added issue templates for bug reports, feature requests, and configuration questions.
- Added GitHub issue template config that redirects vulnerability reports to private security reporting.
- Added pre-merge checklist for the `v1.0.1-public-hardening` branch.
- Added v1.0.1 release notes and public usage examples.
- Extended CI to run `config:validate` and `doctor` diagnostics with a temporary safe CI `.env`.

