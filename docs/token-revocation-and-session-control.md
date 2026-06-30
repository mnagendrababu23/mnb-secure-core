# Token Revocation and Session Control

## Overview

**Token Revocation and Session Control** in MNB Secure Core protects the authentication lifecycle after a user is already logged in. Authentication is not complete when a token or session is issued. A secure application also needs to know when that token or session must stop being trusted.

This feature helps applications manage:

- access token revocation
- refresh token rotation
- refresh token reuse detection
- token family revocation
- safe token introspection
- session registry and validation
- idle and absolute session timeouts
- session rotation
- forced logout
- concurrent session limits
- device/session tracking
- remember-me token safety
- admin session controls

The goal is to prevent stolen tokens, stale sessions, session fixation, refresh-token replay, and unrevoked access after account or permission changes.

---

## Why This Feature Exists

A common mistake is assuming that a signed JWT or session cookie is safe until it naturally expires. In real systems, tokens and sessions often need to be invalidated earlier.

Examples:

- User logs out.
- Password is changed.
- Role or permission changes.
- Account is disabled.
- Admin revokes a suspicious session.
- Refresh token reuse is detected.
- Device is lost.
- Security incident requires forced logout.

Without revocation and session control, old credentials may continue working.

---

## Main Risks Covered

This engine helps reduce risks such as:

- stolen access token reuse
- refresh token replay
- JWT logout gaps
- session hijacking
- session fixation
- stale sessions after password changes
- stale sessions after role or permission changes
- concurrent session abuse
- remember-me token theft
- admin session takeover
- disabled account sessions staying active
- lack of active session visibility

---

## Related Namespaces

```text
Mnb\SecureCore\Token
Mnb\SecureCore\Session
```

Main class groups:

```text
src/Token/*
src/Session/*
```

---

## Configuration

Add or review the `tokens` and `sessions` sections in `config/security.php`.

```php
return [
    'tokens' => [
        'enabled' => true,

        'access_tokens' => [
            'ttl_seconds' => 900,
            'require_jti' => true,
            'require_fingerprint' => true,
            'allow_after_password_change' => false,
            'allow_after_role_change' => false,
        ],

        'refresh_tokens' => [
            'enabled' => true,
            'ttl_seconds' => 2592000,
            'rotation_enabled' => true,
            'reuse_detection_enabled' => true,
            'revoke_family_on_reuse' => true,
            'max_family_size' => 50,
        ],

        'api_tokens' => [
            'enabled' => true,
            'require_hash_storage' => true,
            'allow_plaintext_storage' => false,
            'ttl_seconds' => 7776000,
            'last_used_tracking' => true,
        ],

        'revocation' => [
            'enabled' => true,
            'store' => 'file',
            'path' => __DIR__ . '/../storage/tokens/revoked',
            'check_on_every_request' => true,
            'cleanup_expired_records' => true,
            'retain_revoked_days' => 30,
        ],

        'introspection' => [
            'enabled' => true,
            'include_reason' => false,
            'include_user_id' => false,
            'safe_public_status_only' => true,
        ],
    ],

    'sessions' => [
        'enabled' => true,

        'registry' => [
            'enabled' => true,
            'store' => 'file',
            'path' => __DIR__ . '/../storage/tokens/sessions',
        ],

        'timeouts' => [
            'idle_timeout_seconds' => 1800,
            'absolute_timeout_seconds' => 43200,
            'remember_me_timeout_seconds' => 2592000,
        ],

        'rotation' => [
            'rotate_on_login' => true,
            'rotate_on_privilege_change' => true,
            'rotate_on_password_change' => true,
        ],

        'concurrency' => [
            'enabled' => true,
            'max_sessions_per_user' => 5,
            'max_admin_sessions_per_user' => 2,
            'when_exceeded' => 'revoke_oldest',
        ],

        'device_tracking' => [
            'enabled' => true,
            'fingerprint_user_agent' => true,
            'fingerprint_ip_prefix' => true,
            'detect_location_change' => false,
        ],

        'forced_logout' => [
            'enabled' => true,
            'on_password_change' => true,
            'on_role_change' => true,
            'on_permission_change' => true,
            'on_account_disabled' => true,
            'on_security_incident' => true,
        ],

        'remember_me' => [
            'enabled' => true,
            'rotate_on_use' => true,
            'hash_storage' => true,
            'revoke_on_password_change' => true,
        ],
    ],
];
```

---

## SecurityKernel Usage

Create the kernel normally:

```php
use Mnb\SecureCore\Core\SecurityKernel;

$config = require __DIR__ . '/config/security.php';
$kernel = new SecurityKernel($config);
```

Common services:

```php
$tokenPolicy = $kernel->tokenPolicy();
$tokenRevocation = $kernel->tokenRevocationService();
$tokenValidator = $kernel->tokenValidator();
$tokenIntrospection = $kernel->tokenIntrospectionService();
$refreshRotator = $kernel->refreshTokenRotator();
$refreshReuseDetector = $kernel->refreshTokenReuseDetector();

$sessionPolicy = $kernel->sessionPolicy();
$sessionManager = $kernel->sessionManager();
$sessionValidator = $kernel->sessionValidator();
$sessionRevocation = $kernel->sessionRevocationService();
$sessionRotation = $kernel->sessionRotationService();
$concurrentLimiter = $kernel->concurrentSessionLimiter();
$forcedLogout = $kernel->forcedLogoutService();
$rememberMe = $kernel->rememberMeTokenManager();
$adminSessionControl = $kernel->adminSessionControl();
```

---

## Token Lifecycle

A secure token lifecycle normally looks like this:

```text
Issue token
    ↓
Validate token on request
    ↓
Check expiration
    ↓
Check fingerprint / jti
    ↓
Check revocation store
    ↓
Allow or deny request
```

For refresh tokens:

```text
Issue refresh token
    ↓
Use refresh token
    ↓
Rotate old token to new token
    ↓
Revoke old token
    ↓
Detect reuse if old token appears again
    ↓
Revoke entire token family if reuse is detected
```

---

## Token Types

Typical token types:

```text
access
refresh
api
remember_me
password_reset
email_verification
otp_challenge
```

The library separates token type, token status, metadata, revocation reason, and family tracking.

---

## Creating a Token Record

A token record represents a known token identity. The raw token should not be stored directly.

```php
use Mnb\SecureCore\Token\TokenRecord;
use Mnb\SecureCore\Token\TokenType;
use Mnb\SecureCore\Token\TokenStatus;

$record = new TokenRecord(
    tokenId: 'jti_123456',
    type: TokenType::ACCESS,
    status: TokenStatus::ACTIVE,
    userIdHash: hash('sha256', 'user_1001'),
    familyId: 'family_login_abc',
    issuedAt: time(),
    expiresAt: time() + 900,
    metadata: [
        'device' => 'browser',
        'scope' => 'api',
    ]
);
```

Use hashes or stable internal IDs where possible. Avoid storing raw access tokens or refresh tokens.

---

## Revoking a Token

Use revocation for logout, password changes, admin action, or incident response.

```php
use Mnb\SecureCore\Token\TokenRevocationReason;

$kernel->tokenRevocationService()->revoke(
    tokenId: 'jti_123456',
    tokenType: 'access',
    reason: TokenRevocationReason::LOGOUT,
    expiresAt: time() + 900,
    metadata: [
        'revoked_by' => 'self',
    ]
);
```

After revocation, validation should reject the token.

```php
$result = $kernel->tokenValidator()->validate('jti_123456', 'access');

if (!$result->allowed()) {
    // reject request safely
}
```

---

## Token Revocation Reasons

Common reasons:

```text
logout
admin_revoke
password_changed
role_changed
permission_changed
account_disabled
refresh_reuse_detected
security_incident
expired
compromised
```

The reason should be stored internally for audit and remediation. Public introspection should not expose sensitive internal details unless explicitly configured.

---

## Safe Token Introspection

Token introspection helps admin tools and debugging workflows check whether a token is still active.

```php
$info = $kernel->tokenIntrospectionService()->introspect('jti_123456', 'access');

return json_encode($info->toSafeArray());
```

Safe output example:

```json
{
  "active": false,
  "status": "revoked",
  "safe_reason": "token_not_active",
  "token_type": "access",
  "expires_at": 1719900000
}
```

Do not expose:

```text
raw token
token signature
user PII
private claims
secret keys
internal revocation notes
```

---

## Refresh Token Rotation

Refresh token rotation invalidates the old refresh token each time a new one is issued.

```php
$result = $kernel->refreshTokenRotator()->rotate(
    oldTokenId: 'refresh_A',
    newTokenId: 'refresh_B',
    familyId: 'family_123',
    userIdHash: hash('sha256', 'user_1001'),
    expiresAt: time() + 2592000
);

if (!$result->allowed()) {
    // deny refresh request
}
```

Recommended flow:

```text
1. Client sends refresh token A.
2. Server validates token A.
3. Server revokes token A.
4. Server issues token B.
5. Token B becomes the active refresh token.
6. If token A is used again, reuse is detected.
```

---

## Refresh Token Reuse Detection

If an already-used refresh token appears again, treat it as suspicious.

```php
$reuse = $kernel->refreshTokenReuseDetector()->detect(
    tokenId: 'refresh_A',
    familyId: 'family_123'
);

if ($reuse->detected()) {
    $kernel->tokenRevocationService()->revokeFamily(
        familyId: 'family_123',
        reason: 'refresh_reuse_detected'
    );

    $kernel->forcedLogoutService()->logoutUser(
        userId: 'user_1001',
        reason: 'refresh_reuse_detected'
    );
}
```

This protects users when a refresh token has likely been stolen.

---

## Token Family Tracking

A token family groups refresh tokens from one login/session chain.

Example:

```text
family_123
  refresh_A → rotated and revoked
  refresh_B → active
  refresh_C → future after next rotation
```

If `refresh_A` is reused after rotation, revoke the whole family.

---

## Session Lifecycle

A secure session lifecycle normally looks like this:

```text
Create session
    ↓
Register session
    ↓
Validate on request
    ↓
Check idle timeout
    ↓
Check absolute timeout
    ↓
Check revocation status
    ↓
Update last seen
    ↓
Allow or deny request
```

---

## Creating a Session

```php
use Mnb\SecureCore\Session\SessionContext;

$context = new SessionContext(
    userId: 'user_1001',
    role: 'admin',
    ipAddress: '203.0.113.10',
    userAgent: $_SERVER['HTTP_USER_AGENT'] ?? ''
);

$session = $kernel->sessionManager()->create($context);
```

The session record should contain safe metadata such as:

```text
session_id
user_id hash
device fingerprint
created_at
last_seen_at
idle_expires_at
absolute_expires_at
status
revocation reason
```

---

## Validating a Session

```php
$result = $kernel->sessionValidator()->validate(
    sessionId: $_COOKIE['APP_SESSION'] ?? '',
    context: $context
);

if (!$result->allowed()) {
    // return safe 401/403 response
}
```

Validation should check:

- session exists
- session is active
- idle timeout not exceeded
- absolute timeout not exceeded
- fingerprint is acceptable
- account is still allowed
- session has not been revoked

---

## Session Rotation

Session rotation prevents session fixation and reduces risk after privilege changes.

Rotate after login:

```php
$newSession = $kernel->sessionRotationService()->rotate(
    oldSessionId: $oldSessionId,
    reason: 'login'
);
```

Rotate after privilege change:

```php
$newSession = $kernel->sessionRotationService()->rotate(
    oldSessionId: $currentSessionId,
    reason: 'privilege_change'
);
```

Recommended rotation events:

```text
login
privilege change
password change
role change
admin elevation
remember-me restoration
```

---

## Session Timeout Policy

Two timeout types are important.

### Idle timeout

The session expires after inactivity.

Example:

```text
idle_timeout_seconds = 1800
```

If the user is inactive for 30 minutes, the session should expire.

### Absolute timeout

The session expires after a fixed lifetime, even if the user is active.

Example:

```text
absolute_timeout_seconds = 43200
```

If the user stays active for 12 hours, the session still expires.

---

## Concurrent Session Control

Limit how many active sessions a user can have.

```php
$decision = $kernel->concurrentSessionLimiter()->check(
    userId: 'user_1001',
    role: 'admin'
);

if (!$decision->allowed()) {
    // revoke oldest or block login depending on policy
}
```

Common policy:

```text
Normal users: max 5 sessions
Admins: max 2 sessions
Super admins: max 1 or 2 sessions
```

Recommended overflow behavior:

```text
revoke_oldest
```

This avoids locking out legitimate users while still controlling session growth.

---

## Forced Logout

Forced logout should be called from the application when account security changes.

### Password change

```php
$kernel->forcedLogoutService()->logoutUser(
    userId: 'user_1001',
    reason: 'password_changed'
);
```

### Role change

```php
$kernel->forcedLogoutService()->logoutUser(
    userId: 'user_1001',
    reason: 'role_changed'
);
```

### Account disabled

```php
$kernel->forcedLogoutService()->logoutUser(
    userId: 'user_1001',
    reason: 'account_disabled'
);
```

### Security incident

```php
$kernel->forcedLogoutService()->logoutUser(
    userId: 'user_1001',
    reason: 'security_incident'
);
```

Forced logout should revoke active sessions and related tokens.

---

## Admin Session Control

Admin tools can expose safe controls for session review and revocation.

```php
$sessions = $kernel->adminSessionControl()->listUserSessions('user_1001');
```

Revoke a specific session:

```php
$kernel->adminSessionControl()->revokeSession(
    sessionId: 'sess_abc123',
    reason: 'admin_revoke'
);
```

Revoke all sessions for a user:

```php
$kernel->adminSessionControl()->revokeUserSessions(
    userId: 'user_1001',
    reason: 'admin_revoke'
);
```

Admin views should never show raw tokens or full sensitive fingerprints.

---

## Device Session Tracking

Device tracking helps users and admins understand active sessions.

Safe device metadata may include:

```text
browser family
platform family
last seen time
approximate IP prefix
created time
session status
```

Avoid storing unnecessary high-risk data.

```php
$devices = $kernel->deviceSessionTracker()->listDevices('user_1001');
```

Use device tracking for:

- account security pages
- suspicious session review
- admin support tools
- incident response

---

## Remember-Me Token Safety

Remember-me tokens should be treated like long-lived credentials.

Recommended rules:

```text
random token value
hashed at rest
rotated on every use
revoked on password change
revoked on suspicious reuse
scoped to device/session
```

Create a remember-me token:

```php
$issued = $kernel->rememberMeTokenManager()->issue(
    userId: 'user_1001',
    deviceId: 'device_abc'
);
```

Validate and rotate on use:

```php
$result = $kernel->rememberMeTokenManager()->consumeAndRotate(
    token: $_COOKIE['remember_me'] ?? '',
    deviceId: 'device_abc'
);

if (!$result->allowed()) {
    // deny remember-me restoration
}
```

Never store remember-me tokens in plaintext.

---

## Token and Session Middleware Pattern

A typical request flow:

```php
$tokenResult = $kernel->tokenValidator()->validateFromRequest($request);

if (!$tokenResult->allowed()) {
    return $kernel->errorResponseFactory()->json(
        message: 'Authentication required.',
        status: 401
    );
}

$sessionResult = $kernel->sessionValidator()->validateFromRequest($request);

if (!$sessionResult->allowed()) {
    return $kernel->errorResponseFactory()->json(
        message: 'Session expired or revoked.',
        status: 401
    );
}
```

Recommended middleware order:

```text
1. Request trust / trusted proxy middleware
2. Origin protection middleware
3. Safe error handling middleware
4. Secure request receiving middleware
5. Rate limiting middleware
6. Authentication middleware
7. Token revocation middleware
8. Session validation middleware
9. Authorization middleware
10. CSRF middleware for state-changing web requests
11. Application handler
```

---

## Logout Flow

A safe logout should revoke both token and session.

```php
$kernel->tokenRevocationService()->revoke(
    tokenId: $currentJti,
    tokenType: 'access',
    reason: 'logout',
    expiresAt: $tokenExpiresAt
);

$kernel->sessionRevocationService()->revoke(
    sessionId: $currentSessionId,
    reason: 'logout'
);
```

Response:

```json
{
  "status": true,
  "message": "Logged out successfully."
}
```

Do not return token internals in logout responses.

---

## Password Change Flow

After password change:

```php
// 1. Save new password hash using the authentication/password service.

// 2. Revoke active tokens and sessions.
$kernel->forcedLogoutService()->logoutUser(
    userId: $userId,
    reason: 'password_changed'
);

// 3. Optionally keep current session only if your policy allows it.
```

Recommended production default:

```text
Revoke all old sessions and require login again.
```

---

## Role or Permission Change Flow

After role or permission change:

```php
$kernel->forcedLogoutService()->logoutUser(
    userId: $userId,
    reason: 'role_changed'
);
```

Why this matters:

- Old token may contain stale role claims.
- Old session may still have cached permissions.
- Authorization context should be rebuilt after re-login.

---

## Account Disabled Flow

When account is disabled:

```php
$kernel->forcedLogoutService()->logoutUser(
    userId: $userId,
    reason: 'account_disabled'
);
```

Then future token/session validation should reject access even if the token was previously valid.

---

## API Token Safety

API tokens should be stored as hashes, not plaintext.

Recommended storage fields:

```text
id
name
user_id
hashed_token
prefix
scopes
last_used_at
expires_at
revoked_at
created_at
```

Safe display pattern:

```text
mnb_live_xxxx...abcd
```

Do not display the full token after creation.

---

## Storage Drivers

Recommended stores:

```text
InMemoryTokenRevocationStore       tests only
FileTokenRevocationStore           local/shared hosting/simple apps
DatabaseTokenRevocationStore       production apps with DB

InMemorySessionRegistry            tests only
FileSessionRegistry                local/shared hosting/simple apps
DatabaseSessionRegistry            production apps with DB
```

For production, database-backed stores are usually preferred for multi-node deployments.

---

## Multi-Server Considerations

For apps running on multiple servers, file-based stores may not be enough unless shared storage is used.

Recommended production options:

```text
database-backed token/session registry
Redis-backed implementation if added by app
centralized session storage
sticky sessions only as a temporary option
```

Every web node must be able to check revocation status.

---

## Audit Events

Token events:

```text
token.issued
token.validated
token.revoked
token.revocation_checked
token.refresh_rotated
token.refresh_reuse_detected
token.family_revoked
token.introspection_checked
```

Session events:

```text
session.created
session.validated
session.rotated
session.revoked
session.expired_idle
session.expired_absolute
session.concurrent_limit_exceeded
session.forced_logout
session.device_registered
session.suspicious_change_detected
remember_me.issued
remember_me.rotated
remember_me.revoked
```

Audit records should be secret-safe and should not contain raw token values.

---

## CLI Usage

### Token policy

```bash
php bin/mnb-secure token:policy
```

### Revoke a token

```bash
php bin/mnb-secure token:revoke jti_123456
```

### Introspect a token

```bash
php bin/mnb-secure token:introspect jti_123456
```

### Cleanup expired revocation records

```bash
php bin/mnb-secure token:cleanup
```

### Show token family

```bash
php bin/mnb-secure token:family family_123
```

### Revoke token family

```bash
php bin/mnb-secure token:revoke-family family_123
```

### Session policy

```bash
php bin/mnb-secure session:policy
```

### List sessions

```bash
php bin/mnb-secure session:list
```

### Revoke session

```bash
php bin/mnb-secure session:revoke sess_abc123
```

### Revoke all sessions for user

```bash
php bin/mnb-secure session:revoke-user user_1001
```

### Cleanup expired sessions

```bash
php bin/mnb-secure session:cleanup
```

### Check session

```bash
php bin/mnb-secure session:check sess_abc123
```

### List devices for user

```bash
php bin/mnb-secure session:devices user_1001
```

---

## Vulnerability Matrix Coverage

This feature strengthens coverage for:

```text
stolen_token_reuse
refresh_token_replay
jwt_logout_gap
session_fixation
session_hijacking
unrevoked_session
remember_me_token_theft
token_family_reuse
concurrent_session_abuse
admin_session_takeover
account_disabled_session_active
role_change_session_stale
```

Related controls:

```text
TokenRevocationService
TokenValidator
TokenIntrospectionService
RefreshTokenRotator
RefreshTokenReuseDetector
TokenReplayDetector
SessionManager
SessionValidator
SessionRevocationService
SessionRotationService
ConcurrentSessionLimiter
DeviceSessionTracker
ForcedLogoutService
RememberMeTokenManager
AdminSessionControl
```

Run:

```bash
php bin/mnb-secure vulnerabilities:check stolen_token_reuse
php bin/mnb-secure vulnerabilities:check refresh_token_replay
php bin/mnb-secure vulnerabilities:check session_fixation
php bin/mnb-secure vulnerabilities:check unrevoked_session
```

---

## Pentest and Verification Cases

Recommended verification cases:

```text
PT-TOKEN-001   Revoked access token is rejected
PT-TOKEN-002   Logout revokes active token/session
PT-TOKEN-003   Refresh token rotation invalidates old refresh token
PT-TOKEN-004   Refresh token reuse revokes token family
PT-TOKEN-005   Token is revoked after password change

PT-SESSION-001 Session ID rotates on login
PT-SESSION-002 Session ID rotates after privilege change
PT-SESSION-003 Idle timeout expires session
PT-SESSION-004 Absolute timeout expires session
PT-SESSION-005 Concurrent session limit is enforced
PT-SESSION-006 Admin can revoke user sessions
PT-SESSION-007 Disabled account sessions are forced out
```

Run checklist commands:

```bash
php bin/mnb-secure pentest:checklist
php bin/mnb-secure pentest:matrix
php bin/mnb-secure pentest:verify PT-TOKEN-001
```

---

## Testing Examples

### Revoked token is rejected

```php
$kernel->tokenRevocationService()->revoke(
    tokenId: 'jti_test',
    tokenType: 'access',
    reason: 'logout',
    expiresAt: time() + 900
);

$result = $kernel->tokenValidator()->validate('jti_test', 'access');

assert($result->allowed() === false);
```

### Refresh token reuse revokes family

```php
$kernel->refreshTokenRotator()->rotate(
    oldTokenId: 'refresh_A',
    newTokenId: 'refresh_B',
    familyId: 'family_test',
    userIdHash: hash('sha256', 'user_1'),
    expiresAt: time() + 2592000
);

$reuse = $kernel->refreshTokenReuseDetector()->detect(
    tokenId: 'refresh_A',
    familyId: 'family_test'
);

assert($reuse->detected() === true);
```

### Session expires after idle timeout

```php
$session = $kernel->sessionManager()->create($context);

// Simulate old last_seen_at in test fixture/store.
$result = $kernel->sessionValidator()->validate($session->id(), $context);

assert($result->allowed() === false || $result->status() === 'idle_expired');
```

### Concurrent session limit

```php
for ($i = 0; $i < 6; $i++) {
    $kernel->sessionManager()->create($context);
}

$decision = $kernel->concurrentSessionLimiter()->check('user_1001', 'user');

assert($decision->allowed() === true);
assert($decision->action() === 'revoke_oldest');
```

---

## Production Checklist

Before production, verify:

- [ ] Access tokens include a `jti` or unique token ID.
- [ ] Access token TTL is short.
- [ ] Refresh token rotation is enabled.
- [ ] Refresh token reuse detection is enabled.
- [ ] Revocation store is shared across app nodes.
- [ ] Logout revokes token and session.
- [ ] Password change revokes old sessions/tokens.
- [ ] Role and permission changes trigger forced logout.
- [ ] Account disable triggers forced logout.
- [ ] Session ID rotates on login.
- [ ] Session ID rotates on privilege change.
- [ ] Idle timeout is configured.
- [ ] Absolute timeout is configured.
- [ ] Concurrent session limit is enabled.
- [ ] Admin sessions have stricter limits.
- [ ] Remember-me tokens are hashed at rest.
- [ ] Remember-me tokens rotate on use.
- [ ] Token/session logs do not expose raw token values.
- [ ] Admin session listing redacts sensitive data.
- [ ] CLI diagnostics work in the deployment environment.

---

## Common Mistakes

### Mistake 1: Relying only on JWT expiration

Bad:

```text
User logs out, but JWT remains valid until expiration.
```

Better:

```text
Check token revocation on every authenticated request.
```

### Mistake 2: Not rotating refresh tokens

Bad:

```text
Same refresh token works forever until expiry.
```

Better:

```text
Rotate refresh token on every use and detect reuse.
```

### Mistake 3: Keeping old sessions after password change

Bad:

```text
Password changed, but old browser sessions stay active.
```

Better:

```text
Force logout and revoke token family after password change.
```

### Mistake 4: Storing remember-me tokens in plaintext

Bad:

```text
remember_token column contains raw token.
```

Better:

```text
Store only hashed remember-me token values.
```

### Mistake 5: No shared revocation store in multi-server apps

Bad:

```text
Token revoked on server A, still accepted on server B.
```

Better:

```text
Use database or shared central store for token/session revocation.
```

### Mistake 6: Not revoking sessions after role changes

Bad:

```text
User is demoted, but old admin session still works.
```

Better:

```text
Revoke or rotate sessions after role/permission changes.
```

---

## Recommended Integration Points

Call token/session controls from these app workflows:

```text
login
logout
password change
password reset
role change
permission change
account disabled
admin revoke user
security incident opened
refresh token endpoint
remember-me restore
API token creation/revocation
```

---

## Demo

Run:

```bash
php demos/39-token-revocation-session-control-engine.php
```

The demo shows:

```text
1. Token policy loaded
2. Access token record created
3. Token validated as active
4. Token revoked
5. Revoked token rejected
6. Refresh token rotated
7. Old refresh token reuse detected
8. Token family revoked
9. Session created and registered
10. Session ID rotated on login
11. Concurrent session limit enforced
12. Forced logout after password change
13. Remember-me token rotated
14. Session/device list generated
15. Vulnerability matrix coverage improved
```

---

## Summary

Token Revocation and Session Control gives applications a secure way to manage authentication after login. It closes the gap between token issuance and real-world account security events.

Use it to make sure that:

- logout actually invalidates access
- refresh tokens cannot be replayed safely by attackers
- stale sessions die after account changes
- session IDs rotate at security boundaries
- admins can revoke suspicious sessions
- remember-me tokens are safe
- token/session events are audited

This is a critical part of production authentication security.
