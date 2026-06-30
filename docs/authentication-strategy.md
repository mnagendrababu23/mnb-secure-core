# Authentication Strategy

**Package:** `mnb/mnb-secure-core`  
**Release line:** `MNB Secure Core v1.0.1`  
**Document type:** Detailed feature documentation and code usage  
**Feature area:** Login, registration, password hashing, password policy, bearer tokens, optional authentication, session authentication, webhook signature authentication, named authentication profiles, token validation, token/session lifecycle integration, audit logging, safe failures

---

## 1. Overview

The **Authentication Strategy** centralizes how an application proves the identity of a user, API client, webhook sender, admin, or internal system.

It answers questions like:

```text
Which authentication method should this route use?
Is authentication required or optional?
Is this bearer token valid?
Is this session active?
Is this webhook signature trusted?
Does this authenticated identity have the required role, scope, or permission?
Should failed login attempts reveal whether the user exists?
Should authentication failures be audited?
Should tokens be revoked after logout, password change, role change, or incident response?
```

The goal is to avoid scattered authentication logic inside controllers. Instead of checking tokens, sessions, passwords, and webhook signatures manually in every route, you define **named authentication strategies** and reuse them consistently.

Typical route mapping:

```text
Public route       → no authentication or optional bearer authentication
API route          → required bearer authentication
Admin route        → required bearer authentication + admin role
Web route          → required PHP session authentication
Webhook endpoint   → required HMAC/signature authentication
Internal route     → required bearer token with system scope/role
```

---

## 2. Why Authentication Strategy Matters

Authentication mistakes usually happen when every route handles identity slightly differently.

Common risks:

```text
Missing authentication on one sensitive route
Accepting expired or revoked tokens
Returning different login errors for valid and invalid users
Weak password policy
Session fixation
Unrotated sessions after privilege changes
Refresh token replay
Logout that does not invalidate tokens
Webhook endpoint accepting unsigned requests
Admin route checking login but not admin role
Token values leaking into logs
```

The authentication strategy layer reduces those risks by providing:

```text
Named strategy profiles
Safe password hashing
Password policy validation
Opaque bearer token support
Session authentication support
HMAC/webhook signature authentication
Optional authentication mode
Role/scope/permission gates
Audit trail for success and failure
Safe generic failure messages
Integration with token revocation and session control
```

Recommended flow:

```text
Incoming request
    ↓
Secure request receiving
    ↓
Request trust / host / origin checks
    ↓
Rate limit and suspicious request checks
    ↓
Authentication strategy middleware
    ↓
AuthContext attached to request
    ↓
Authorization policy / permission guard
    ↓
Tenant boundary / resource policy
    ↓
Controller/service logic
```

---

## 3. Main Classes

Authentication is mainly built around these classes:

```text
Mnb\SecurityCore\Auth\AuthenticationStrategy
Mnb\SecurityCore\Auth\AuthenticationRegistry
Mnb\SecurityCore\Auth\AuthenticationResult
Mnb\SecurityCore\Auth\AuthContext
Mnb\SecurityCore\Auth\AuthWorkflowService
Mnb\SecurityCore\Auth\UserProviderInterface
Mnb\SecurityCore\Auth\PasswordHasher
Mnb\SecurityCore\Auth\PasswordPolicy
Mnb\SecurityCore\Auth\PasswordPolicyResult
Mnb\SecurityCore\Auth\OpaqueTokenService
Mnb\SecurityCore\Auth\SessionGuard
Mnb\SecurityCore\Auth\PermissionGuard
Mnb\SecurityCore\Auth\AuthAuditEvents

Mnb\SecurityCore\Http\Middleware\AuthenticationMiddleware
Mnb\SecurityCore\Http\WebhookSignatureVerifier
```

Related upgrade-35 token/session lifecycle classes may also be used with authentication:

```text
Mnb\SecurityCore\Token\TokenRevocationService
Mnb\SecurityCore\Token\TokenValidator
Mnb\SecurityCore\Token\RefreshTokenRotator
Mnb\SecurityCore\Token\RefreshTokenReuseDetector
Mnb\SecurityCore\Session\SessionManager
Mnb\SecurityCore\Session\SessionValidator
Mnb\SecurityCore\Session\SessionRevocationService
Mnb\SecurityCore\Session\SessionRotationService
Mnb\SecurityCore\Session\ForcedLogoutService
Mnb\SecurityCore\Session\RememberMeTokenManager
```

---

## 4. Installation

Install from Packagist:

```bash
composer require mnb/mnb-secure-core
```

Bootstrap Composer autoloading:

```php
<?php

require __DIR__ . '/vendor/autoload.php';

use Mnb\SecurityCore\Core\SecurityKernel;

$config = require __DIR__ . '/vendor/mnb/mnb-secure-core/config/security.php';
$kernel = new SecurityKernel($config);
```

If you copy the config into your app, load your app config instead:

```php
$config = require __DIR__ . '/config/security.php';
$kernel = new SecurityKernel($config);
```

---

## 5. Configuration

The main authentication configuration lives under the `authentication` block.

Example:

```php
'authentication' => [
    'enabled' => true,

    'defaults' => [
        'failure_message' => 'Authentication required',
        'audit' => true,
        'required' => true,
    ],

    'strategies' => [
        'api_bearer' => [
            'type' => 'bearer',
            'required' => true,
            'rate_policy' => 'api',
            'audit' => true,
        ],

        'optional_bearer' => [
            'type' => 'bearer',
            'required' => false,
            'audit' => false,
        ],

        'admin_bearer' => [
            'type' => 'bearer',
            'required' => true,
            'roles' => ['admin', 'super_admin'],
            'rate_policy' => 'api',
            'audit' => true,
        ],

        'web_session' => [
            'type' => 'session',
            'required' => true,
            'audit' => true,
        ],

        'webhook_hmac' => [
            'type' => 'signature',
            'required' => true,
            'scopes' => ['webhook:receive'],
            'signature' => [
                'signature_header' => $_ENV['WEBHOOK_SIGNATURE_HEADER'] ?? 'X-Signature',
                'timestamp_header' => $_ENV['WEBHOOK_TIMESTAMP_HEADER'] ?? 'X-Timestamp',
                'algorithm' => $_ENV['WEBHOOK_SIGNATURE_ALGORITHM'] ?? 'sha256',
                'secret' => $_ENV['WEBHOOK_SECRET'] ?? '',
                'tolerance_seconds' => (int)($_ENV['WEBHOOK_TIMESTAMP_TOLERANCE'] ?? 300),
            ],
            'audit' => true,
        ],

        'internal_system' => [
            'type' => 'bearer',
            'required' => true,
            'scopes' => ['system:*'],
            'roles' => ['system', 'internal_system'],
            'audit' => true,
        ],
    ],

    'password_policy' => [
        'min_length' => 12,
        'max_length' => 128,
        'require_mixed_case' => false,
        'require_number' => false,
        'require_symbol' => false,
        'block_common_passwords' => true,
        'block_user_context' => true,
    ],

    'login' => [
        'rate_policy' => 'login',
        'generic_failure_message' => 'Invalid credentials',
        'audit_failures' => true,
        'ttl_seconds' => 2592000,
    ],
],
```

---

## 6. Strategy Types

### 6.1 Bearer Strategy

Bearer authentication validates an `Authorization: Bearer ...` token.

Use for:

```text
REST APIs
Mobile apps
Single-page app APIs
Internal service APIs
Admin APIs with token-based access
```

Example:

```php
'api_bearer' => [
    'type' => 'bearer',
    'required' => true,
    'rate_policy' => 'api',
    'audit' => true,
],
```

### 6.2 Optional Bearer Strategy

Optional bearer authentication allows a route to work for guests but attaches an `AuthContext` if a valid token is present.

Use for:

```text
Public feed with personalized results when logged in
Public article with optional user bookmark status
Public search with optional account limits
```

Example:

```php
'optional_bearer' => [
    'type' => 'bearer',
    'required' => false,
    'audit' => false,
],
```

### 6.3 Session Strategy

Session authentication reads the current PHP session and creates an `AuthContext`.

Use for:

```text
Server-rendered web dashboards
Admin panels
Traditional web apps
```

Example:

```php
'web_session' => [
    'type' => 'session',
    'required' => true,
    'audit' => true,
],
```

### 6.4 Signature Strategy

Signature authentication validates a request signature, commonly for webhooks.

Use for:

```text
Webhook endpoints
Signed internal callbacks
Provider notifications
```

Example:

```php
'webhook_hmac' => [
    'type' => 'signature',
    'required' => true,
    'scopes' => ['webhook:receive'],
    'signature' => [
        'signature_header' => 'X-Signature',
        'timestamp_header' => 'X-Timestamp',
        'algorithm' => 'sha256',
        'secret' => $_ENV['WEBHOOK_SECRET'] ?? '',
        'tolerance_seconds' => 300,
    ],
],
```

### 6.5 None Strategy

The `none` strategy can be used for a named public route profile when you still want route metadata to say explicitly that authentication is not required.

Example:

```php
'public' => [
    'type' => 'none',
    'required' => false,
    'audit' => false,
],
```

---

## 7. AuthContext

After successful authentication, the middleware attaches an `AuthContext` to the request.

It contains:

```text
authenticated flag
user ID
scopes
permissions
roles
token record metadata
session metadata
```

Example usage:

```php
use Mnb\SecurityCore\Auth\AuthContext;

$auth = $request->attribute(AuthContext::ATTRIBUTE);

if ($auth instanceof AuthContext && $auth->isAuthenticated()) {
    $userId = $auth->id();
    $roles = $auth->roles();
    $permissions = $auth->permissions();
}
```

Recommended defensive usage:

```php
use Mnb\SecurityCore\Auth\PermissionGuard;

$auth = PermissionGuard::requireAuthenticated($request);

if ($auth->can('profile.update')) {
    // Continue safely.
}
```

---

## 8. Authentication Middleware Usage

### 8.1 API Bearer Middleware

```php
use Mnb\SecurityCore\Core\SecurityKernel;

$middleware = $kernel->authenticationMiddleware('api_bearer');
```

Route example:

```php
$response = $middleware->process($request, function ($request) {
    $auth = $request->attribute('auth');

    return Response::json([
        'status' => true,
        'user_id' => $auth?->id(),
    ]);
});
```

If the token is missing or invalid, the middleware returns:

```json
{
  "status": false,
  "message": "Authentication required"
}
```

### 8.2 Admin Route Middleware

```php
$adminAuth = $kernel->authenticationMiddleware('admin_bearer');
```

The strategy can require roles:

```php
'admin_bearer' => [
    'type' => 'bearer',
    'required' => true,
    'roles' => ['admin', 'super_admin'],
],
```

If the user is authenticated but missing the required role, the middleware returns a safe `403 Forbidden` response.

### 8.3 Optional Auth Middleware

```php
$optional = $kernel->authenticationMiddleware('optional_bearer');
```

This is useful when a route supports both guest and logged-in users.

```php
$response = $optional->process($request, function ($request) {
    $auth = $request->attribute('auth');

    return Response::json([
        'status' => true,
        'viewer' => $auth?->isAuthenticated() ? 'user' : 'guest',
    ]);
});
```

---

## 9. Middleware Order

Authentication should not be the first middleware. It should run after request normalization, origin checks, content-type checks, suspicious request checks, and rate limiting.

Recommended order:

```php
$pipeline = $kernel->middlewarePipeline([
    $kernel->requestIdMiddleware(),
    $kernel->requestTrustMiddleware(),
    $kernel->serverIdentityProtectionMiddleware(),
    $kernel->httpsMiddleware(),
    $kernel->trustedHostMiddleware(),
    $kernel->requestSizeMiddleware(),
    $kernel->contentTypeMiddleware(),
    $kernel->jsonBodyParserMiddleware(),
    $kernel->suspiciousRequestMiddleware(),
    $kernel->securityHeadersMiddleware(),
    $kernel->rateLimitMiddleware('api'),
    $kernel->authenticationMiddleware('api_bearer'),
    $kernel->authorizationMiddleware('profile.update'),
    $kernel->autoAuditMiddleware(),
]);
```

Reason:

```text
Reject malformed/oversized/suspicious requests before token validation.
Attach request IDs before audit logs.
Validate host/proxy/origin before trusting request metadata.
Rate-limit login and API routes before expensive downstream work.
```

---

## 10. UserProviderInterface

`AuthWorkflowService` uses a `UserProviderInterface` so the package does not force a specific database schema.

Interface responsibilities:

```text
Find user by login identifier
Return password hash
Return user ID
Return roles
Return permissions
Return scopes
Check active/inactive status
```

Example implementation:

```php
use Mnb\SecurityCore\Auth\UserProviderInterface;

final class ArrayUserProvider implements UserProviderInterface
{
    public function __construct(private array $users) {}

    public function findByIdentifier(string $identifier): ?array
    {
        foreach ($this->users as $user) {
            if (($user['email'] ?? '') === $identifier) {
                return $user;
            }
        }

        return null;
    }

    public function passwordHash(array $user): string
    {
        return (string)$user['password_hash'];
    }

    public function userId(array $user): int|string
    {
        return $user['id'];
    }

    public function roles(array $user): array
    {
        return $user['roles'] ?? [];
    }

    public function permissions(array $user): array
    {
        return $user['permissions'] ?? [];
    }

    public function scopes(array $user): array
    {
        return $user['scopes'] ?? [];
    }

    public function isActive(array $user): bool
    {
        return (bool)($user['active'] ?? true);
    }
}
```

---

## 11. Password Hashing

Use `PasswordHasher` instead of manual hashing.

```php
$hasher = $kernel->passwordHasher();

$hash = $hasher->hash('correct horse battery staple');

if ($hasher->verify('correct horse battery staple', $hash)) {
    // Password matched.
}

if ($hasher->needsRehash($hash)) {
    $newHash = $hasher->hash('correct horse battery staple');
    // Store the new hash.
}
```

Do not use:

```php
md5($password);
sha1($password);
hash('sha256', $password);
```

Password hashing needs a password-hashing algorithm, not a generic hash.

---

## 12. Password Policy

Password policy validates password strength before registration or password change.

Example:

```php
$policy = $kernel->passwordPolicy();

$result = $policy->validate('password123', [
    'email' => 'nagendra@example.com',
    'name' => 'Nagendra',
]);

if ($result->failed()) {
    return Response::json([
        'status' => false,
        'message' => 'Password policy failed.',
        'errors' => $result->errors(),
    ], 422);
}
```

Recommended production policy:

```php
'password_policy' => [
    'min_length' => 12,
    'max_length' => 128,
    'require_mixed_case' => false,
    'require_number' => false,
    'require_symbol' => false,
    'block_common_passwords' => true,
    'block_user_context' => true,
],
```

Note: forcing symbols and numbers is optional. Longer passphrases with common-password blocking are usually easier for users and safer than short complex passwords.

---

## 13. Login Workflow

`AuthWorkflowService` provides a safe login workflow with:

```text
Generic failure messages
Password verification
Active-user check
Token issuing
AuthContext creation
Audit logging
```

Example:

```php
use Mnb\SecurityCore\Auth\AuthWorkflowService;

$users = new ArrayUserProvider([
    [
        'id' => 1,
        'email' => 'admin@example.com',
        'password_hash' => $kernel->passwordHasher()->hash('VeryStrongPassphrase123'),
        'roles' => ['admin'],
        'permissions' => ['dashboard.view', 'users.manage'],
        'scopes' => ['api:*'],
        'active' => true,
    ],
]);

$auth = $kernel->authWorkflow($users);

$result = $auth->login(
    identifier: 'admin@example.com',
    password: 'VeryStrongPassphrase123',
    scopes: ['api:read'],
    ttlSeconds: 3600,
    deviceId: 'device_123',
    deviceName: 'Chrome on Windows',
    context: [
        'ip' => $_SERVER['REMOTE_ADDR'] ?? null,
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? null,
    ]
);

if ($result->failed()) {
    return Response::json([
        'status' => false,
        'message' => $result->safeMessage(),
    ], $result->status());
}

return Response::json([
    'status' => true,
    'token' => $result->plainToken(),
    'expires_at' => $result->metadata('expires_at'),
]);
```

Important: return the plain token only once, during login/token creation. Store only the hash server-side.

---

## 14. Registration Workflow

`AuthWorkflowService::register()` lets the app own the actual user creation while the library handles password policy and audit flow.

Example:

```php
$result = $auth->register([
    'name' => 'Nagendra',
    'email' => 'nagendra@example.com',
    'password' => 'LongSafePassphrase123',
], function (array $data) use ($kernel) {
    return [
        'id' => 10,
        'name' => $data['name'],
        'email' => $data['email'],
        'password_hash' => $kernel->passwordHasher()->hash($data['password']),
        'roles' => ['user'],
        'permissions' => ['profile.view'],
        'scopes' => ['api:read'],
        'active' => true,
    ];
});

if ($result->failed()) {
    return Response::json([
        'status' => false,
        'message' => $result->safeMessage(),
        'errors' => $result->errors(),
    ], $result->status());
}
```

Recommended app-side registration protections:

```text
Validate input fields
Normalize email
Check duplicate email safely
Hash password with PasswordHasher
Do not log raw password
Create default roles/scopes safely
Send verification email through safe queue/background job if required
```

---

## 15. Opaque Token Service

`OpaqueTokenService` issues random opaque tokens and stores only their hashes.

### 15.1 Issue Token

```php
$tokens = $kernel->opaqueTokenService();

$issued = $tokens->issue(
    userId: 1,
    scopes: ['api:read'],
    deviceId: 'device_123',
    deviceName: 'Chrome on Windows',
    ttlSeconds: 3600,
    permissions: ['profile.view'],
    roles: ['user']
);

$plainToken = $issued['plain_token'];
$record = $issued['record'];
```

### 15.2 Validate Token

```php
$record = $tokens->validate(
    plainToken: $plainToken,
    ip: $_SERVER['REMOTE_ADDR'] ?? null,
    userAgent: $_SERVER['HTTP_USER_AGENT'] ?? null
);

if ($record === null) {
    // Invalid, expired, or revoked.
}
```

### 15.3 Revoke Token

```php
$tokens->revoke($plainToken);
```

For advanced revocation, refresh token rotation, token families, and forced logout, use the upgrade-35 token/session control services.

---

## 16. Token Revocation Integration

Authentication should integrate with token revocation and session control.

Recommended events that should revoke tokens/sessions:

```text
Logout
Password changed
Role changed
Permission changed
Account disabled
Refresh token reuse detected
Security incident opened
Admin manually revoked access
```

Example logout flow:

```php
$token = $request->bearerToken();

if ($token !== null) {
    $kernel->opaqueTokenService()->revoke($token);
}

// If using upgrade-35 token revocation service:
// $kernel->tokenRevocationService()->revoke($jti, 'logout');

return Response::json([
    'status' => true,
    'message' => 'Logged out.',
]);
```

Example forced logout after password change:

```php
$userId = 10;

// Revoke active sessions for this user.
$kernel->forcedLogoutService()->logoutUser(
    userId: $userId,
    reason: 'password_changed'
);

// Revoke token records/families depending on your token model.
$kernel->tokenRevocationService()->revokeUserTokens(
    userId: $userId,
    reason: 'password_changed'
);
```

If your local class method names differ, keep the same principle: password/role/account changes must invalidate old authentication state.

---

## 17. Session Authentication

For traditional PHP session auth, use `SessionGuard`.

### 17.1 Login Session

```php
$session = new \Mnb\SecurityCore\Auth\SessionGuard();

$session->login(
    user: [
        'id' => 10,
        'school_id' => 2,
        'branch_id' => 5,
        'academic_year_id' => 2026,
        'role' => 'admin',
    ],
    permissions: ['dashboard.view', 'students.manage'],
    roles: ['admin'],
    scopes: ['web:*']
);
```

`SessionGuard::login()` regenerates the session ID to reduce session fixation risk.

### 17.2 Check Session

```php
if (!$session->check()) {
    return Response::json([
        'status' => false,
        'message' => 'Authentication required',
    ], 401);
}
```

### 17.3 Logout Session

```php
$session->logout();
```

Recommended secure cookie options:

```php
$session->start([
    'secure' => true,
    'http_only' => true,
    'same_site' => 'Lax',
]);
```

For highly sensitive admin panels, use:

```php
'same_site' => 'Strict'
```

if your UX and cross-site flows support it.

---

## 18. Webhook Signature Authentication

Webhook endpoints should not rely only on obscurity or a secret URL. Use signature authentication.

Recommended route flow:

```php
$pipeline = $kernel->middlewarePipeline([
    $kernel->requestIdMiddleware(),
    $kernel->requestSizeMiddleware(),
    $kernel->jsonBodyParserMiddleware(),
    $kernel->authenticationMiddleware('webhook_hmac'),
]);
```

The strategy should include a real secret:

```php
'webhook_hmac' => [
    'type' => 'signature',
    'required' => true,
    'signature' => [
        'signature_header' => 'X-Signature',
        'timestamp_header' => 'X-Timestamp',
        'algorithm' => 'sha256',
        'secret' => $_ENV['WEBHOOK_SECRET'],
        'tolerance_seconds' => 300,
    ],
],
```

Production checklist:

```text
Use a 32+ character random webhook secret.
Require timestamp validation.
Reject stale timestamps.
Never log raw webhook secret.
Keep webhook request size limits small.
Apply rate limiting to webhook endpoint.
```

---

## 19. PermissionGuard Usage

`PermissionGuard` is a simple helper for checking authentication and capabilities from either `Request` or `AuthContext`.

### 19.1 Require Login

```php
use Mnb\SecurityCore\Auth\PermissionGuard;

$auth = PermissionGuard::requireAuthenticated($request);
```

### 19.2 Require Scope

```php
$auth = PermissionGuard::requireScope($request, 'api:read');
```

### 19.3 Require Permission

```php
$auth = PermissionGuard::requirePermission($request, 'students.update');
```

### 19.4 Require Role

```php
$auth = PermissionGuard::requireRole($request, 'admin');
```

Authentication proves identity. Authorization should still decide whether that identity can perform the action.

---

## 20. Route Strategy Examples

### 20.1 Public Route

```php
'public' => [
    'type' => 'none',
    'required' => false,
    'audit' => false,
],
```

### 20.2 API Route

```php
'api_bearer' => [
    'type' => 'bearer',
    'required' => true,
    'scopes' => ['api:read'],
    'rate_policy' => 'api',
],
```

### 20.3 Admin API Route

```php
'admin_bearer' => [
    'type' => 'bearer',
    'required' => true,
    'roles' => ['admin', 'super_admin'],
    'permissions' => ['admin.access'],
],
```

### 20.4 Internal System Route

```php
'internal_system' => [
    'type' => 'bearer',
    'required' => true,
    'scopes' => ['system:*'],
    'roles' => ['system', 'internal_system'],
],
```

### 20.5 User Profile Update Route

```php
'profile_update' => [
    'type' => 'bearer',
    'required' => true,
    'permissions' => ['profile.update'],
    'rate_policy' => 'api',
],
```

---

## 21. Safe Failure Responses

Authentication failures should not leak details.

Bad:

```json
{
  "message": "User exists but password is wrong"
}
```

Good:

```json
{
  "status": false,
  "message": "Invalid credentials"
}
```

For middleware failures, a typical response is:

```json
{
  "status": false,
  "message": "Authentication required"
}
```

For authenticated users missing roles/scopes/permissions:

```json
{
  "status": false,
  "message": "Forbidden"
}
```

The technical reason should go to audit logs, not frontend responses.

---

## 22. Audit Events

Authentication should produce safe audit events such as:

```text
login.success
login.failed
register.success
register.failed
password.policy_failed
token.issued
token.validated
token.rejected
token.revoked
auth.allowed
auth.denied
session.authenticated
signature.authenticated
```

Logs should include fingerprints instead of raw secrets.

Safe:

```text
token_fingerprint=fp_xxxxx
identifier_fingerprint=fp_xxxxx
```

Unsafe:

```text
password=secret123
Authorization: Bearer raw-token-here
WEBHOOK_SECRET=...
```

---

## 23. Authentication + Authorization Relationship

Do not treat authentication as authorization.

Authentication answers:

```text
Who are you?
```

Authorization answers:

```text
Are you allowed to do this action on this resource?
```

Recommended flow:

```php
$pipeline = $kernel->middlewarePipeline([
    $kernel->authenticationMiddleware('api_bearer'),
    $kernel->authorizationMiddleware('students.update'),
]);
```

Inside services, you can also enforce:

```php
$auth = PermissionGuard::requireAuthenticated($request);
PermissionGuard::requirePermission($auth, 'students.update');
```

For tenant-aware data access, pass the authenticated context into the database/trust-boundary layer.

---

## 24. Authentication + Tenant Boundaries

Authentication identifies the user. Tenant boundary controls determine which school, organization, branch, or account data the user can access.

Session metadata may include:

```text
school_id
branch_id
academic_year_id
```

Example:

```php
$auth = PermissionGuard::requireAuthenticated($request);

$tenant = [
    'school_id' => $auth->metadata('school_id'),
    'branch_id' => $auth->metadata('branch_id'),
    'academic_year_id' => $auth->metadata('academic_year_id'),
];
```

Never trust tenant IDs sent in request bodies over authenticated/session context.

Bad:

```php
$schoolId = $_POST['school_id'];
```

Good:

```php
$schoolId = $auth->metadata('school_id');
```

---

## 25. Authentication + Rate Limiting

Login and token validation should be protected by rate limiting.

Recommended policies:

```text
login      → strict per IP + identifier fingerprint
api        → per token/user/IP
admin      → stricter than public API
webhook    → per provider/IP/signature profile
```

Example strategy config:

```php
'api_bearer' => [
    'type' => 'bearer',
    'rate_policy' => 'api',
],

'login' => [
    'rate_policy' => 'login',
],
```

Recommended pipeline:

```php
$kernel->rateLimitMiddleware('login');
// then login handler
```

---

## 26. Authentication + Queue/Background Jobs

Do not put raw tokens or passwords into queue payloads.

Bad:

```php
$dispatcher->dispatch('send_report', [
    'token' => $plainToken,
    'password' => $password,
]);
```

Good:

```php
$dispatcher->dispatch('send_report', [
    'user_id' => $auth->id(),
    'report_id' => $reportId,
]);
```

For background jobs, use a safe job context:

```text
job_id
user_id
safe role/scope snapshot if needed
request_id
operation name
```

Re-check permissions for sensitive jobs when they run, especially if role/session state may have changed since dispatch.

---

## 27. Production Environment Variables

Recommended environment values:

```env
AUTHENTICATION_ENABLED=true
AUTH_TOKEN_TTL_SECONDS=3600
PASSWORD_MIN_LENGTH=12
PASSWORD_MAX_LENGTH=128
PASSWORD_BLOCK_COMMON=true
PASSWORD_BLOCK_USER_CONTEXT=true
WEBHOOK_SECRET=replace_with_32_plus_character_random_secret
WEBHOOK_SIGNATURE_HEADER=X-Signature
WEBHOOK_TIMESTAMP_HEADER=X-Timestamp
WEBHOOK_SIGNATURE_ALGORITHM=sha256
WEBHOOK_TIMESTAMP_TOLERANCE=300
```

If using token/session revocation:

```env
TOKEN_REVOCATION_STORE=file
SESSION_REGISTRY_STORE=file
```

Use real random secrets in production. Do not commit `.env` files.

---

## 28. Example Full API Login Endpoint

```php
use Mnb\SecurityCore\Core\SecurityKernel;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;

$config = require __DIR__ . '/config/security.php';
$kernel = new SecurityKernel($config);

$request = Request::fromGlobals();
$data = $request->json() ?: [];

$users = new DatabaseUserProvider($pdo);
$auth = $kernel->authWorkflow($users);

$result = $auth->login(
    identifier: (string)($data['email'] ?? ''),
    password: (string)($data['password'] ?? ''),
    scopes: ['api:read'],
    ttlSeconds: 3600,
    deviceId: (string)($data['device_id'] ?? ''),
    deviceName: (string)($data['device_name'] ?? ''),
    context: [
        'ip' => $request->ip(),
        'user_agent' => $request->header('user-agent'),
        'request_id' => $request->attribute('request_id'),
    ]
);

if ($result->failed()) {
    return Response::json([
        'status' => false,
        'message' => $result->safeMessage(),
    ], $result->status())->send();
}

return Response::json([
    'status' => true,
    'message' => 'Login successful.',
    'token_type' => 'Bearer',
    'access_token' => $result->plainToken(),
    'expires_at' => $result->metadata('expires_at'),
])->send();
```

---

## 29. Example Protected API Endpoint

```php
use Mnb\SecurityCore\Auth\PermissionGuard;
use Mnb\SecurityCore\Http\Response;

$pipeline = $kernel->middlewarePipeline([
    $kernel->requestIdMiddleware(),
    $kernel->requestSizeMiddleware(),
    $kernel->jsonBodyParserMiddleware(),
    $kernel->rateLimitMiddleware('api'),
    $kernel->authenticationMiddleware('api_bearer'),
]);

$response = $pipeline->handle($request, function ($request) {
    $auth = PermissionGuard::requireAuthenticated($request);

    return Response::json([
        'status' => true,
        'message' => 'Protected data loaded.',
        'user_id' => $auth->id(),
    ]);
});

$response->send();
```

---

## 30. Example Admin Endpoint

```php
$pipeline = $kernel->middlewarePipeline([
    $kernel->requestIdMiddleware(),
    $kernel->rateLimitMiddleware('api'),
    $kernel->authenticationMiddleware('admin_bearer'),
]);

$response = $pipeline->handle($request, function ($request) {
    $auth = PermissionGuard::requireRole($request, 'admin');

    return Response::json([
        'status' => true,
        'message' => 'Admin dashboard loaded.',
    ]);
});
```

---

## 31. Testing Authentication

### 31.1 Password Policy Test

```php
$policy = $kernel->passwordPolicy();
$result = $policy->validate('password', ['email' => 'test@example.com']);

assert($result->failed());
assert(isset($result->errors()['common']) || isset($result->errors()['min_length']));
```

### 31.2 Token Issue/Validate/Revoke Test

```php
$tokens = $kernel->opaqueTokenService();

$issued = $tokens->issue(1, ['api:read'], ttlSeconds: 60);
$plain = $issued['plain_token'];

assert($tokens->validate($plain) !== null);

$tokens->revoke($plain);

assert($tokens->validate($plain) === null);
```

### 31.3 Strategy Registry Test

```php
$registry = $kernel->authenticationRegistry();

assert($registry->has('api_bearer'));
assert($registry->get('api_bearer')->type() === 'bearer');
```

### 31.4 Middleware Missing Token Test

```php
$middleware = $kernel->authenticationMiddleware('api_bearer');

$response = $middleware->process($requestWithoutToken, function () {
    throw new RuntimeException('Should not reach route');
});

assert($response->status() === 401);
```

### 31.5 Admin Role Failure Test

```php
// Issue a token for a user without admin role.
// Call admin_bearer strategy.
// Expect 403 Forbidden.
```

---

## 32. CLI Commands Related to Authentication

Depending on the installed upgrade set, useful commands include:

```bash
php bin/mnb-secure config:validate
php bin/mnb-secure doctor
php bin/mnb-secure production:readiness
```

Token/session lifecycle commands from upgrade 35:

```bash
php bin/mnb-secure token:policy
php bin/mnb-secure token:revoke <jti>
php bin/mnb-secure token:introspect <jti>
php bin/mnb-secure token:cleanup
php bin/mnb-secure token:family <family_id>
php bin/mnb-secure token:revoke-family <family_id>

php bin/mnb-secure session:policy
php bin/mnb-secure session:list
php bin/mnb-secure session:revoke <session_id>
php bin/mnb-secure session:revoke-user <user_id>
php bin/mnb-secure session:cleanup
php bin/mnb-secure session:check <session_id>
php bin/mnb-secure session:devices <user_id>
```

Vulnerability checks may include:

```bash
php bin/mnb-secure vulnerabilities:check stolen_token_reuse
php bin/mnb-secure vulnerabilities:check refresh_token_replay
php bin/mnb-secure vulnerabilities:check session_fixation
php bin/mnb-secure vulnerabilities:check unrevoked_session
```

---

## 33. Production Checklist

Before using authentication in production, verify:

```text
[ ] Authentication is enabled.
[ ] Login routes are rate-limited.
[ ] Login failures use a generic message.
[ ] Passwords are hashed with PasswordHasher or password_hash(), never MD5/SHA1.
[ ] Password policy is enabled for registration and password changes.
[ ] Tokens are stored hashed, not plaintext.
[ ] Bearer tokens use HTTPS only.
[ ] Token TTL is limited.
[ ] Logout revokes tokens/sessions.
[ ] Password change revokes old sessions/tokens.
[ ] Role/permission change revokes or rotates sessions.
[ ] Admin routes require admin role/permission, not just login.
[ ] Webhook strategies use a real 32+ character secret.
[ ] Webhook signatures validate timestamp freshness.
[ ] Session cookies use HttpOnly.
[ ] Session cookies use Secure in HTTPS production.
[ ] Session IDs rotate on login.
[ ] Remember-me tokens are hashed and rotated.
[ ] Raw tokens/passwords are never logged.
[ ] Audit logs record safe fingerprints, not secrets.
```

---

## 34. Common Mistakes

### Mistake 1: Checking only login but not role

Bad:

```php
PermissionGuard::requireAuthenticated($request);
// admin action continues
```

Good:

```php
PermissionGuard::requireRole($request, 'admin');
```

or use:

```php
$kernel->authenticationMiddleware('admin_bearer');
```

### Mistake 2: Returning detailed login failures

Bad:

```text
Email exists but password is wrong.
```

Good:

```text
Invalid credentials.
```

### Mistake 3: Not revoking after password change

Bad:

```text
User changes password, old mobile token still works.
```

Good:

```text
Password change triggers forced logout and token revocation.
```

### Mistake 4: Putting secrets in queue payloads

Bad:

```php
['access_token' => $plainToken]
```

Good:

```php
['user_id' => $userId, 'operation_id' => $operationId]
```

### Mistake 5: Treating JWT/logout as solved automatically

If your app uses stateless JWTs, logout requires a revocation strategy, short TTL, token introspection, or session versioning. Upgrade 35 provides revocation/session control components for this.

---

## 35. Recommended Auth Architecture

For API/mobile apps:

```text
Login endpoint
    ↓
AuthWorkflowService validates credentials
    ↓
Password policy / PasswordHasher
    ↓
Opaque token issued or app JWT issued with jti
    ↓
Token revocation/session registry records identity state
    ↓
Client sends Bearer token
    ↓
AuthenticationMiddleware validates token
    ↓
AuthorizationMiddleware checks action/resource
```

For web apps:

```text
Login form
    ↓
AuthWorkflowService validates credentials
    ↓
SessionGuard login rotates session ID
    ↓
Session registry records device/session
    ↓
Session auth middleware validates session
    ↓
Authorization/tenant boundary protects resources
```

For webhooks:

```text
Provider request
    ↓
Request size/content-type check
    ↓
Signature timestamp tolerance check
    ↓
HMAC signature verification
    ↓
AuthenticationMiddleware creates webhook AuthContext
    ↓
Webhook handler queues safe background job
```

---

## 36. Minimal Quick Start

```php
use Mnb\SecurityCore\Core\SecurityKernel;
use Mnb\SecurityCore\Auth\PermissionGuard;

require __DIR__ . '/vendor/autoload.php';

$config = require __DIR__ . '/vendor/mnb/mnb-secure-core/config/security.php';
$kernel = new SecurityKernel($config);

$pipeline = $kernel->middlewarePipeline([
    $kernel->requestIdMiddleware(),
    $kernel->rateLimitMiddleware('api'),
    $kernel->authenticationMiddleware('api_bearer'),
]);

$response = $pipeline->handle($request, function ($request) {
    $auth = PermissionGuard::requireAuthenticated($request);

    return \Mnb\SecurityCore\Http\Response::json([
        'status' => true,
        'user_id' => $auth->id(),
    ]);
});
```

---

## 37. Summary

The **Authentication Strategy** provides a centralized way to protect identity-sensitive routes with named, reusable profiles.

It gives you:

```text
Bearer authentication
Optional bearer authentication
Session authentication
Webhook signature authentication
Admin/internal route authentication
Password hashing
Password policy validation
Login and registration workflow helpers
AuthContext for downstream authorization
Token issue/validate/revoke support
Token/session revocation integration
Safe failure messages
Audit logging
```

Best practice:

```text
Authenticate early.
Authorize separately.
Audit safely.
Return generic failures.
Rate-limit login.
Rotate sessions.
Revoke stale tokens.
Never log secrets.
```

