# v1.0.1 Pre-Merge Checklist

Use this checklist before merging the `v1.0.1-public-hardening` branch into `main`.

## 1. Branch safety

- [ ] Changes are on a feature/review branch, not directly committed to `main`.
- [ ] Branch name clearly describes the work, for example `v1.0.1-public-hardening`.
- [ ] Pull request target is `main`.
- [ ] Version stays `v1.0.1`; no new version number is introduced.

## 2. Public API compatibility

- [ ] No existing namespace was removed.
- [ ] No existing public class was removed.
- [ ] No existing public method was removed.
- [ ] Existing constructor behavior remains backward-compatible.
- [ ] New behavior is additive or protected by config.
- [ ] Existing demos and examples still work.

## 3. Local verification

Run from the repository root:

```bash
php tests/run-tests.php
php demos/run-all-demos.php
php bin/mnb-secure config:validate
php bin/mnb-secure doctor
```

For `doctor`, make sure `.env` contains a 32+ character `APP_KEY`. Example for local release checks:

```env
APP_ENV=ci
APP_DEBUG=false
APP_KEY=0123456789012345678901234567890123456789
TRUSTED_HOSTS=localhost,example.test
```

Expected result:

- [ ] Tests pass.
- [ ] Demos pass.
- [ ] `config:validate` returns valid JSON and no blocking errors.
- [ ] `doctor` returns valid JSON.
- [ ] Any `doctor` warnings are understood and acceptable.

## 4. Composer and package readiness

Run locally if Composer is installed:

```bash
composer validate --strict --no-check-publish
```

Check:

- [ ] `composer.json` license is public-use friendly.
- [ ] `composer.json` does not contain an inline `version` field.
- [ ] Required PHP extensions are declared.
- [ ] `bin/mnb-secure` is executable on Unix/macOS.
- [ ] Release archive does not include `.git`.
- [ ] Release archive does not include a nested duplicate `mnb-secure-core/` project copy.

## 5. Security review

- [ ] No secrets or real credentials are committed.
- [ ] Secret scanner is clean or findings are false positives.
- [ ] Tokens are logged only as safe fingerprints, never raw tokens.
- [ ] Upload policies block executable extensions and double extensions.
- [ ] SQL identifiers are validated before dynamic table/column use.
- [ ] Forwarded headers are trusted only from configured trusted proxies.
- [ ] Security headers remain enabled by default.
- [ ] Production warnings are documented when a strict setting is intentionally disabled.

## 6. Documentation review

- [ ] `README.md` links to quickstart, examples, install checklist, and release notes.
- [ ] `SECURITY.md` explains private vulnerability reporting.
- [ ] `CHANGELOG.md` includes the v1.0.1 hardening summary.
- [ ] New examples do not require optional dependencies unless documented.
- [ ] Example config uses placeholders, not real credentials.

## 7. GitHub review readiness

- [ ] PR template is filled.
- [ ] Issue templates are present.
- [ ] CI workflow passes.
- [ ] Reviewer notes call out any risky files.
- [ ] Release notes are attached or linked from the PR.

## 8. Merge and tag flow

After the PR is approved and merged:

```bash
git checkout main
git pull origin main
git tag v1.0.1
git push origin v1.0.1
```

Only create the tag after the final `main` branch contains the approved v1.0.1 state.
