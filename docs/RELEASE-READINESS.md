# Release Readiness Pack

This pack helps prepare `mnb-secure-core v1.0.1` for public GitHub use.

## Included GitHub files

- `.github/PULL_REQUEST_TEMPLATE.md`
- `.github/ISSUE_TEMPLATE/bug_report.yml`
- `.github/ISSUE_TEMPLATE/feature_request.yml`
- `.github/ISSUE_TEMPLATE/config_question.yml`
- `.github/ISSUE_TEMPLATE/config.yml`

## Included release docs

- `docs/PRE-MERGE-CHECKLIST.md`
- `docs/RELEASE-NOTES-v1.0.1.md`
- `docs/PUBLIC-USAGE-EXAMPLES.md`

## Maintainer workflow

1. Push work to `v1.0.1-public-hardening`.
2. Open PR into `main`.
3. Complete the PR template.
4. Run CI and local diagnostics.
5. Review public API compatibility.
6. Merge only after checks pass.
7. Tag `v1.0.1` from `main`.

## User support workflow

Use issue templates to separate:

- bugs,
- feature requests,
- configuration questions.

Security vulnerabilities should not be posted as public issues. Direct users to `SECURITY.md` or GitHub private vulnerability reporting.


## Auto audit, CORS, and suggestions add-on

Additional v1.0.1 additions include:

- `AutoAuditLogger` and `AutoAuditMiddleware` for safe automatic add/edit/delete/submission/email/auth/password-verification audit events.
- Improved `CorsMiddleware` and `CorsPolicy` with credential-safe origin reflection, preflight validation, exposed headers, origin patterns, max-age, and private-network opt-in.
- `AutoSuggestionEngine` for suggestions from typed words or pasted PHP code snippets.
- Kernel helpers: `autoAuditLogger()`, `autoAuditMiddleware()`, `corsMiddleware()`, and `suggestionEngine()`.
