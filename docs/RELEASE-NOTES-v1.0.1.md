# mnb-secure-core v1.0.1 Release Notes

`v1.0.1` is a public package hardening release. It keeps the original library direction but improves public-use readiness, production diagnostics, integration examples, and developer onboarding.

## Release theme

Public package hardening without breaking existing users.

## Highlights

- Public license and release hygiene improvements.
- Auth context and permission guard for token/session-aware apps.
- Security config validator and CLI doctor diagnostics.
- Safer storage driver resolution for file, database, and Redis drivers.
- Named rate-limit policies for IP, user, route, path, method, and auth-aware keys.
- Request trust layer for real client IP, forwarded proto/host/port, trusted proxies, and CDN-aware origin protection.
- Upload security profiles for images, documents, videos, archives, and strict production mode.
- Structured audit logger for auth, token, upload, admin, database, sensitive, and system actions.
- Security headers builder with CSP nonce support, HSTS rules, and Permissions-Policy presets.
- Plain PHP and Slim integration examples.
- Production quickstart files, install checklist, and first-token bootstrap workflow.
- Release readiness templates for GitHub pull requests and issues.

## Backward compatibility

This release is intended to be additive:

- Existing namespaces are preserved.
- Existing demos are preserved.
- Existing `RateLimiterInterface::attempt()` behavior is preserved.
- Existing middleware patterns are preserved.
- New helpers are added without forcing an application rewrite.

## Recommended verification

Run from the repository root:

```bash
php tests/run-tests.php
php demos/run-all-demos.php
php bin/mnb-secure config:validate
php bin/mnb-secure doctor
```

Composer users should also run:

```bash
composer validate --strict --no-check-publish
```

## Important production notes

- Set a real 32+ character `APP_KEY` before production use.
- Configure `TRUSTED_HOSTS` and, when behind a CDN/reverse proxy, configure `TRUSTED_PROXIES`.
- Keep storage, token, audit, backup, and quarantine paths outside public web roots.
- Enable HTTPS and HSTS only after TLS is stable.
- Prefer ClamAV/composite upload scanning with fail-closed behavior for production uploads.
- Do not log raw API tokens; use the structured audit helpers that store safe fingerprints.

## GitHub release checklist

Before creating the final tag:

- [ ] PR reviewed and merged into `main`.
- [ ] CI passed.
- [ ] Tests and demos passed locally.
- [ ] `doctor` blocking issues are zero for release config.
- [ ] Release ZIP excludes `.git` and duplicate nested project folders.
- [ ] `LICENSE`, `SECURITY.md`, `CHANGELOG.md`, and docs are present.

Tag after merge:

```bash
git checkout main
git pull origin main
git tag v1.0.1
git push origin v1.0.1
```


## Auto audit, CORS, and suggestions add-on

Additional v1.0.1 additions include:

- `AutoAuditLogger` and `AutoAuditMiddleware` for safe automatic add/edit/delete/submission/email/auth/password-verification audit events.
- Improved `CorsMiddleware` and `CorsPolicy` with credential-safe origin reflection, preflight validation, exposed headers, origin patterns, max-age, and private-network opt-in.
- `AutoSuggestionEngine` for suggestions from typed words or pasted PHP code snippets.
- Kernel helpers: `autoAuditLogger()`, `autoAuditMiddleware()`, `corsMiddleware()`, and `suggestionEngine()`.

## Request input validation and sanitization add-on

Additional v1.0.1 additions include:

- Expanded `InputValidator` with common request rules for body/query validation.
- Added `InputSanitizer` for safe normalization, blocked-key removal, allow-listed fields, max depth, and max string length.
- Added `InputValidationMiddleware` for route/path/method-based validation before controllers run.
- Added request helpers for sanitized/validated data: `queryParams()`, `body()`, `validated()`, `withQuery()`, and `withBody()`.
- Added kernel helpers: `inputValidator()`, `inputSanitizer()`, and `inputValidationMiddleware()`.
- Added config/env and production/config validator checks for request validation policy safety.

### Trust Zone Boundary Engine

v1.0.1 now includes a production-ready trust boundary engine:

- `TrustBoundaryPolicy`
- `TrustBoundaryDecision`
- `TrustBoundaryContext`
- `TrustZoneResolver`
- `TrustBoundaryRegistry`
- `TrustBoundaryMiddleware`

This connects trust zones, data classes, resources, tenant context, permissions/scopes/roles, safe output filtering, and structured audit events.
