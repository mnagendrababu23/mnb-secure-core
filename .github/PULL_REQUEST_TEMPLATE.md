## Summary

Describe the change and why it is needed.

## Scope

- [ ] Runtime/core code
- [ ] Configuration
- [ ] Tests
- [ ] Documentation/examples only
- [ ] Release/package metadata

## v1.0.1 compatibility

- [ ] No public namespace was removed
- [ ] No public method was removed
- [ ] Existing demos still pass
- [ ] Existing tests still pass
- [ ] This change stays under `v1.0.1`

## Security checklist

- [ ] No secrets, tokens, passwords, private keys, or real credentials are committed
- [ ] New config values are safe by default
- [ ] Production behavior is documented when relevant
- [ ] Errors returned to users stay safe and do not expose internals
- [ ] Audit/security logging avoids raw tokens and sensitive values
- [ ] Upload, SQL, header, proxy, auth, and rate-limit changes were reviewed when touched

## Local verification

Run before requesting merge:

```bash
php tests/run-tests.php
php demos/run-all-demos.php
php bin/mnb-secure config:validate
php bin/mnb-secure doctor
```

For `doctor`, use a local `.env` with a real 32+ character `APP_KEY`.

## Notes for reviewer

Mention risky areas, migration notes, or anything the maintainer should manually test.
