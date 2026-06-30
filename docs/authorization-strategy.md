# Authorization Strategy

**Package:** `mnb/mnb-secure-core`  
**Release line:** `MNB Secure Core v1.0.1`  
**Document type:** Detailed feature documentation and code usage  
**Feature area:** Authorization policies, roles, permissions, scopes, tenant-aware access control, field-level authorization, resource ownership checks, trust-boundary linkage, safe denial responses, audit logging, database integration

---

## 1. Overview

The **Authorization Strategy** controls what an authenticated or guest actor is allowed to do after identity has been established.

Authentication answers:

```text
Who is this actor?
```

Authorization answers:

```text
What is this actor allowed to access or modify?
```

In `mnb-secure-core`, authorization is designed around **named policies**. A policy describes the resource, action, required roles, required permissions, required scopes, tenant requirements, data classification, trust boundary, field-level visibility, and audit behavior.

Typical examples:

```text
students.read       → School admin can read students inside the same tenant.
students.update     → School admin can update only safe student fields.
students.delete     → Only super admin can delete student records.
backup.run          → Only trusted internal/system actors can run backup jobs.
public.read         → Public users can read public content only.
```

The strategy is intentionally **deny-by-default**. If a policy is missing, a role is missing, a permission is missing, a scope is missing, or tenant ownership fails, access is denied with a safe response.

---

## 2. Why Authorization Strategy Matters

Authorization bugs are some of the most serious application vulnerabilities.

Common risks:

```text
Broken access control
IDOR / object-level authorization failure
Cross-tenant data leakage
Role bypass
Permission mismatch
Over-broad admin access
Field-level data exposure
User can update protected fields
Missing authorization on one route
Unsafe direct database access
Different controllers using different permission rules
Leaking denial reasons to attackers
```

The Authorization Strategy reduces these risks by providing:

```text
Central policy registry
Deny-by-default behavior
Role checks
Permission checks
Scope checks
Tenant-aware resource ownership checks
Data-class checks
Trust-boundary linkage
Field-level read/write filtering
Safe denial responses
Audit events for denials and high-risk access
Integration with secure database policies
Integration with request profiles and middleware
```

Recommended request flow:

```text
Incoming request
    ↓
Secure request receiving
    ↓
Request trust / origin / host protection
    ↓
Rate limiting
    ↓
Authentication
    ↓
Authorization policy check
    ↓
Tenant boundary check
    ↓
Database/resource policy check
    ↓
Controller/service logic
```

---

## 3. Main Classes

Authorization is mainly built around these classes:

```text
Mnb\SecurityCore\Authorization\AuthorizationPolicy
Mnb\SecurityCore\Authorization\AuthorizationRegistry
Mnb\SecurityCore\Authorization\AuthorizationDecision
Mnb\SecurityCore\Authorization\AuthorizationContext
Mnb\SecurityCore\Authorization\AuthorizationAuditEvents
Mnb\SecurityCore\Authorization\FieldAuthorization
Mnb\SecurityCore\Authorization\PolicyExplainer
Mnb\SecurityCore\Authorization\ResourceResolverInterface

Mnb\SecurityCore\Http\Middleware\AuthorizationMiddleware
```

Related tenant and legacy/simple authorization classes:

```text
Mnb\SecurityCore\Authz\TenantContext
Mnb\SecurityCore\Authz\TenantGuard
Mnb\SecurityCore\Authz\PermissionGuard
Mnb\SecurityCore\Authz\PolicyRegistry
```

Related authentication context:

```text
Mnb\SecurityCore\Auth\AuthContext
```

Related trust-boundary classes:

```text
Mnb\SecurityCore\Trust\TrustBoundaryRegistry
Mnb\SecurityCore\Trust\TrustBoundaryPolicy
Mnb\SecurityCore\Trust\TrustZoneResolver
```

Related database layer:

```text
Mnb\SecurityCore\Database\SecureDatabase
Mnb\SecurityCore\Database\TableSecurityPolicy
Mnb\SecurityCore\Database\DatabasePolicyRegistry
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

If you publish/copy the config into your application, load your app config instead:

```php
$config = require __DIR__ . '/config/security.php';
$kernel = new SecurityKernel($config);
```

---

## 5. Configuration

Authorization configuration lives under the `authorization` block.

Example:

```php
'authorization' => [
    'enabled' => true,
    'deny_by_default' => true,
    'audit_denials' => true,
    'hide_denial_reasons' => true,

    'policies' => [
        'public.read' => [
            'resource' => 'public_pages',
            'actions' => ['read'],
            'data_classes' => ['public'],
            'audit' => false,
            'fields' => [
                'read' => [
                    '*' => ['title', 'slug', 'body'],
                ],
            ],
        ],

        'students.read' => [
            'resource' => 'students',
            'actions' => ['read'],
            'roles' => ['school_admin', 'super_admin'],
            'permissions' => ['student.view'],
            'scopes' => ['students:read', 'student.view'],
            'tenant_required' => true,
            'data_classes' => ['internal', 'confidential', 'sensitive'],
            'trust_boundary' => 'students.read',
            'audit' => true,
            'fields' => [
                'read' => [
                    'school_admin' => ['id', 'name', 'email', 'parent_phone', 'school_id', 'branch_id'],
                    'super_admin' => ['*'],
                ],
            ],
        ],

        'students.update' => [
            'resource' => 'students',
            'actions' => ['update'],
            'roles' => ['school_admin', 'super_admin'],
            'permissions' => ['student.update'],
            'scopes' => ['students:update', 'student.update'],
            'tenant_required' => true,
            'data_classes' => ['sensitive'],
            'trust_boundary' => 'students.update',
            'audit' => true,
            'fields' => [
                'write' => [
                    'school_admin' => ['name', 'email', 'parent_phone', 'branch_id'],
                    'super_admin' => ['*'],
                ],
            ],
        ],

        'students.delete' => [
            'resource' => 'students',
            'actions' => ['delete'],
            'roles' => ['super_admin'],
            'permissions' => ['student.delete'],
            'scopes' => ['students:delete', 'student.delete'],
            'tenant_required' => true,
            'data_classes' => ['sensitive'],
            'trust_boundary' => 'students.delete',
            'audit' => true,
        ],
    ],
],
```

### Important defaults

Recommended production defaults:

```php
'authorization' => [
    'enabled' => true,
    'deny_by_default' => true,
    'audit_denials' => true,
    'hide_denial_reasons' => true,
],
```

Meaning:

```text
No registered policy → deny
Denied access → audit
Frontend denial message → safe and generic
Internal logs/audit → can contain safe diagnostic reason
```

---

## 6. Policy Fields Explained

### `resource`

The logical resource protected by the policy.

Examples:

```text
students
teachers
payments
reports
backups
api_tokens
```

### `actions`

Allowed actions for the policy.

Examples:

```text
read
create
update
delete
restore
export
approve
backup
run
```

If the request action does not match, authorization fails.

### `roles`

High-level user roles.

Examples:

```text
super_admin
school_admin
teacher
student
parent
internal_system
```

Roles are useful for broad access grouping. Do not rely on roles alone for sensitive operations. Use permissions/scopes and tenant checks too.

### `permissions`

Fine-grained application permissions.

Examples:

```text
student.view
student.update
student.delete
report.export
backup.run
```

Permissions are good for admin panels where roles may map to many abilities.

### `scopes`

Token/API scopes.

Examples:

```text
students:read
students:update
system:backup
webhook:receive
```

Scopes are useful for API clients, service tokens, and OAuth-style access.

### `tenant_required`

When true, the policy requires a tenant context and validates that the protected resource belongs to the same tenant.

Common tenant fields:

```text
school_id
branch_id
academic_year_id
```

### `data_classes`

Allowed data classification values.

Examples:

```text
public
internal
confidential
sensitive
highly_sensitive
```

This connects authorization with data-boundary rules.

### `trust_boundary`

Links the authorization policy to a named trust-boundary policy.

Example:

```php
'trust_boundary' => 'students.read'
```

This is useful when the resource needs both:

```text
Authorization decision
Trust-zone / data-boundary decision
```

### `fields`

Controls field-level read/write access.

Example:

```php
'fields' => [
    'read' => [
        'school_admin' => ['id', 'name', 'email'],
        'super_admin' => ['*'],
    ],
    'write' => [
        'school_admin' => ['name', 'email'],
        'super_admin' => ['*'],
    ],
],
```

This helps prevent:

```text
Sensitive field exposure
Mass assignment
Over-posting
Protected-field update
```

---

## 7. Creating an Authorization Registry

Use the kernel:

```php
use Mnb\SecurityCore\Core\SecurityKernel;

$config = require __DIR__ . '/config/security.php';
$kernel = new SecurityKernel($config);

$authorization = $kernel->authorizationRegistry();
```

You can also fetch a single policy:

```php
$policy = $kernel->authorizationPolicy('students.read');
```

Explain a policy for diagnostics/admin UI:

```php
$explanation = $authorization->explain('students.read');

print_r($explanation);
```

Example result shape:

```php
[
    'name' => 'students.read',
    'resource' => 'students',
    'actions' => ['read'],
    'roles' => ['school_admin', 'super_admin'],
    'permissions' => ['student.view'],
    'scopes' => ['students:read', 'student.view'],
    'tenant_required' => true,
    'data_classes' => ['internal', 'confidential', 'sensitive'],
    'trust_boundary' => 'students.read',
    'audit' => true,
    'fields' => [...],
]
```

---

## 8. Manual Authorization Check

Manual checks are useful inside services, controllers, jobs, and CLI commands.

```php
use Mnb\SecurityCore\Auth\AuthContext;
use Mnb\SecurityCore\Authz\TenantContext;

$auth = new AuthContext(
    authenticated: true,
    userId: 101,
    scopes: ['students:read'],
    permissions: ['student.view'],
    roles: ['school_admin']
);

$tenant = new TenantContext(
    userId: 101,
    schoolId: 10,
    branchId: 2,
    academicYearId: 2026,
    roles: ['school_admin'],
    permissions: ['student.view']
);

$student = [
    'id' => 5001,
    'name' => 'Anil',
    'school_id' => 10,
    'branch_id' => 2,
    'academic_year_id' => 2026,
];

$decision = $kernel->authorizationRegistry()->decide(
    policyName: 'students.read',
    resource: $student,
    action: 'read',
    resourceName: 'students',
    dataClass: 'sensitive',
    auth: $auth,
    tenant: $tenant
);

if ($decision->denied()) {
    http_response_code($decision->statusCode());
    echo json_encode([
        'status' => false,
        'message' => $decision->safeMessage(),
        'code' => $decision->code(),
    ]);
    exit;
}

// Continue safely.
```

Check the result:

```php
if ($decision->allowed()) {
    // Authorized.
}

if ($decision->denied()) {
    // Block request.
}
```

Convert to debug/admin array:

```php
$result = $decision->toArray();
```

Do not expose the full decision result to public users in production if it contains internal policy context.

---

## 9. Middleware Usage

The kernel can create authorization middleware:

```php
$middleware = $kernel->authorizationMiddleware(
    policyName: 'students.read',
    action: 'read',
    resourceName: 'students',
    dataClass: 'sensitive'
);
```

In a middleware pipeline:

```php
use Mnb\SecurityCore\Http\MiddlewarePipeline;
use Mnb\SecurityCore\Http\Response;

$pipeline = new MiddlewarePipeline([
    $kernel->requestTrustMiddleware(),
    $kernel->secureRequestMiddleware('authenticated'),
    $kernel->authenticationMiddleware('api_bearer'),
    $kernel->authorizationMiddleware('students.read', null, 'read', 'students', 'sensitive'),
]);

$response = $pipeline->handle($request, function ($request) {
    return Response::json([
        'status' => true,
        'message' => 'Student list allowed.',
    ]);
});
```

If authorization fails, middleware returns a safe JSON response:

```json
{
  "status": false,
  "message": "Access denied",
  "code": "authorization_denied"
}
```

When `hide_denial_reasons` is true, public users receive a safe generic message. Internal audit logs can still contain the safe reason/code.

---

## 10. Resource Resolver Usage

For object-level authorization, the policy needs the target resource record.

Example route:

```text
GET /students/5001
```

The authorization middleware can use a resolver callback:

```php
$resourceResolver = function ($request, string $policyName): ?array {
    $studentId = $request->routeParam('id') ?? $request->query('id');

    // Fetch only the minimal fields needed for authorization.
    return findStudentAuthorizationRecord($studentId);
};

$middleware = $kernel->authorizationMiddleware(
    policyName: 'students.read',
    resourceResolver: $resourceResolver,
    action: 'read',
    resourceName: 'students',
    dataClass: 'sensitive'
);
```

Example resolver result:

```php
[
    'id' => 5001,
    'school_id' => 10,
    'branch_id' => 2,
    'academic_year_id' => 2026,
    'status' => 'active',
]
```

The tenant guard can then block cross-tenant access.

---

## 11. ResourceResolverInterface Usage

For larger apps, create a resolver class:

```php
use Mnb\SecurityCore\Authorization\ResourceResolverInterface;
use Mnb\SecurityCore\Http\Request;

final class StudentResourceResolver implements ResourceResolverInterface
{
    public function resolve(Request $request, string $policyName): ?array
    {
        $studentId = $request->routeParam('id') ?? $request->query('id');

        if (!$studentId) {
            return null;
        }

        return findStudentAuthorizationRecord($studentId);
    }
}
```

Register it in middleware:

```php
$middleware = $kernel->authorizationMiddleware(
    'students.read',
    new StudentResourceResolver(),
    'read',
    'students',
    'sensitive'
);
```

This keeps controller code clean.

---

## 12. Tenant-Aware Authorization

For multi-tenant apps, tenant checks are critical.

Example tenant context:

```php
use Mnb\SecurityCore\Authz\TenantContext;

$tenant = new TenantContext(
    userId: 101,
    schoolId: 10,
    branchId: 2,
    academicYearId: 2026,
    roles: ['school_admin'],
    permissions: ['student.view']
);
```

Example protected record:

```php
$record = [
    'id' => 5001,
    'school_id' => 11,
    'branch_id' => 2,
    'academic_year_id' => 2026,
];
```

Since `school_id` differs from the tenant context, access is denied when the policy has:

```php
'tenant_required' => true
```

This protects against IDOR:

```text
User changes /students/5001 to /students/5002
System checks that the record belongs to the same tenant
Cross-tenant record is denied even if the user has student.view permission
```

---

## 13. Field-Level Authorization

Authorization is not only about route access. It also controls fields.

Example record:

```php
$student = [
    'id' => 5001,
    'name' => 'Anil',
    'email' => 'anil@example.com',
    'parent_phone' => '9999999999',
    'medical_notes' => 'Sensitive note',
    'internal_risk_score' => 82,
    'school_id' => 10,
    'branch_id' => 2,
];
```

Filter readable fields:

```php
$safeStudent = $kernel->authorizationRegistry()->filterReadableFields(
    'students.read',
    $request,
    $student
);
```

If the user has role `school_admin`, and the policy allows only:

```php
['id', 'name', 'email', 'parent_phone', 'school_id', 'branch_id']
```

then the result excludes:

```text
medical_notes
internal_risk_score
```

Filter writable fields:

```php
$safeUpdate = $kernel->authorizationRegistry()->filterWritableFields(
    'students.update',
    $request,
    $input
);
```

This helps block over-posting:

```php
$input = [
    'name' => 'New Name',
    'role' => 'super_admin',       // removed
    'school_id' => 99,             // removed unless explicitly allowed
    'internal_risk_score' => 100,  // removed
];
```

---

## 14. Roles, Permissions, and Scopes

The policy can require roles, permissions, and scopes.

Example:

```php
'roles' => ['school_admin', 'super_admin'],
'permissions' => ['student.view'],
'scopes' => ['students:read'],
```

By default, a policy with configured roles/permissions/scopes means the authenticated actor must satisfy the configured requirements used by the registry.

Recommended design:

```text
Roles       → broad human/user grouping
Permissions → fine-grained app ability
Scopes      → API/token ability
Tenant      → ownership boundary
Fields      → read/write column visibility
```

Do not use only `role=admin` for everything. Use permissions and tenant boundaries for sensitive actions.

---

## 15. Wildcard Grants

`AuthContext` supports wildcard matching for roles/scopes/permissions.

Examples:

```text
*              → all
students:*     → all student scopes matching students:...
```

Example:

```php
$auth = new AuthContext(
    authenticated: true,
    userId: 1,
    scopes: ['students:*'],
    permissions: [],
    roles: ['school_admin']
);
```

This can satisfy:

```text
students:read
students:update
students:export
```

Use wildcard grants carefully. In production, prefer explicit permissions unless the actor is a trusted system or super-admin.

---

## 16. Linking Authorization to Trust Boundaries

Authorization can reference a trust boundary:

```php
'trust_boundary' => 'students.read'
```

That means access is allowed only if both checks pass:

```text
Authorization policy allows actor/action/resource
Trust boundary allows zone/data/resource transition
```

Useful cases:

```text
Public → internal data should be blocked
Admin → sensitive student data should require tenant context
Internal job → highly sensitive backup action should require system zone
```

Example:

```php
$decision = $kernel->authorizationRegistry()->decide(
    'students.read',
    $request,
    $student,
    'read',
    'students',
    'sensitive'
);
```

If the authorization policy passes but the trust boundary denies the transition, the final decision is denied.

---

## 17. Authorization with Request Receiving Profiles

Request profiles can include authorization requirements so middleware can be assembled consistently.

Example profile-style config pattern:

```php
'request_receiving' => [
    'profiles' => [
        'students_read_api' => [
            'authentication' => 'api_bearer',
            'authorization' => 'students.read',
            'authorization_action' => 'read',
            'authorization_resource' => 'students',
            'authorization_data_class' => 'sensitive',
        ],
    ],
],
```

Then the app can create a secure profile pipeline instead of manually adding every middleware.

This avoids mistakes like:

```text
Route has authentication but forgot authorization
Route has authorization but no tenant resource resolver
Route uses correct permission but wrong data class
```

---

## 18. Authorization with Secure Database

Database security and authorization should work together.

Recommended flow:

```text
1. Authenticate request
2. Authorize policy/action/resource
3. Use SecureDatabase with TableSecurityPolicy
4. Apply tenant scope automatically
5. Filter fields before returning response
```

Example:

```php
$decision = $kernel->authorizationRegistry()->decide(
    policyName: 'students.read',
    request: $request,
    action: 'read',
    resourceName: 'students',
    dataClass: 'sensitive'
);

if ($decision->denied()) {
    return Response::json([
        'status' => false,
        'message' => $decision->safeMessage(),
        'code' => $decision->code(),
    ], $decision->statusCode());
}

$rows = $kernel->secureDatabase()->search(
    $studentTablePolicy,
    $tenantContext,
    ['status' => ['eq' => 'active']]
);

$safeRows = array_map(
    fn (array $row) => $kernel->authorizationRegistry()->filterReadableFields('students.read', $request, $row),
    $rows
);
```

This prevents both:

```text
Unauthorized query execution
Authorized route returning too many fields
```

---

## 19. Authorization in Background Jobs

Queue/background jobs should also authorize sensitive operations.

Example job handler:

```php
final class ExportStudentsJobHandler
{
    public function handle(array $payload): array
    {
        $auth = AuthContext::fromTokenRecord($payload['actor'] ?? []);
        $tenant = new TenantContext(
            userId: $auth->id(),
            schoolId: $payload['school_id'] ?? null,
            branchId: $payload['branch_id'] ?? null,
            academicYearId: $payload['academic_year_id'] ?? null,
            roles: $auth->roles(),
            permissions: $auth->permissions()
        );

        $decision = $this->kernel->authorizationRegistry()->decide(
            'students.read',
            resource: ['school_id' => $tenant->schoolId],
            action: 'read',
            resourceName: 'students',
            dataClass: 'sensitive',
            auth: $auth,
            tenant: $tenant
        );

        if ($decision->denied()) {
            throw new RuntimeException('Job is not authorized.');
        }

        // Continue export.
        return ['exported' => true];
    }
}
```

Do not assume background jobs are trusted automatically. A job can still process user-scoped data and must preserve authorization context safely.

---

## 20. Safe Denial Responses

Public denial response should be generic:

```json
{
  "status": false,
  "message": "Access denied",
  "code": "authorization_denied"
}
```

Do not expose detailed reasons publicly, such as:

```text
required role is missing
resource does not belong to tenant context
trust boundary denied
policy missing
```

Those details are useful internally but can help attackers map your permission model.

Recommended config:

```php
'hide_denial_reasons' => true
```

---

## 21. Audit Events

Authorization can generate audit events for decisions.

Main event names include:

```text
access.allowed
access.denied
permission.denied
role.denied
scope.denied
tenant.denied
field.denied
policy.missing
```

Example audited details may include:

```text
policy name
resource name
resource fingerprint
action
data class
safe actor metadata
tenant identifiers
safe reason code
request ID
```

Sensitive values should not be logged directly. Use fingerprints, IDs, and safe metadata.

---

## 22. Common Policy Examples

### Public content

```php
'public.read' => [
    'resource' => 'public_pages',
    'actions' => ['read'],
    'data_classes' => ['public'],
    'audit' => false,
]
```

### Admin dashboard

```php
'admin.dashboard' => [
    'resource' => 'admin_dashboard',
    'actions' => ['read'],
    'roles' => ['admin', 'super_admin'],
    'permissions' => ['admin.dashboard.view'],
    'data_classes' => ['internal'],
    'audit' => true,
]
```

### Own profile update

```php
'profile.update' => [
    'resource' => 'profiles',
    'actions' => ['update'],
    'permissions' => ['profile.update'],
    'tenant_required' => false,
    'data_classes' => ['confidential'],
    'fields' => [
        'write' => [
            'authenticated' => ['name', 'email', 'phone', 'language'],
        ],
    ],
    'audit' => true,
]
```

### Highly sensitive backup

```php
'backup.run' => [
    'resource' => 'backups',
    'actions' => ['backup'],
    'roles' => ['internal_system', 'system'],
    'scopes' => ['system:backup', 'system:*'],
    'data_classes' => ['highly_sensitive'],
    'trust_boundary' => 'backup.run',
    'audit' => true,
]
```

---

## 23. Testing Authorization

### Test allowed decision

```php
$decision = $kernel->authorizationRegistry()->decide(
    'students.read',
    resource: ['school_id' => 10, 'branch_id' => 2],
    action: 'read',
    resourceName: 'students',
    dataClass: 'sensitive',
    auth: new AuthContext(true, 101, ['students:read'], ['student.view'], ['school_admin']),
    tenant: new TenantContext(101, 10, 2, 2026, ['school_admin'], ['student.view'])
);

assert($decision->allowed());
```

### Test denied missing permission

```php
$decision = $kernel->authorizationRegistry()->decide(
    'students.read',
    resource: ['school_id' => 10],
    action: 'read',
    resourceName: 'students',
    dataClass: 'sensitive',
    auth: new AuthContext(true, 101, ['students:read'], [], ['school_admin']),
    tenant: new TenantContext(101, 10, 2, 2026, ['school_admin'], [])
);

assert($decision->denied());
assert($decision->code() === 'permission.denied');
```

### Test tenant denial

```php
$decision = $kernel->authorizationRegistry()->decide(
    'students.read',
    resource: ['school_id' => 99],
    action: 'read',
    resourceName: 'students',
    dataClass: 'sensitive',
    auth: new AuthContext(true, 101, ['students:read'], ['student.view'], ['school_admin']),
    tenant: new TenantContext(101, 10, 2, 2026, ['school_admin'], ['student.view'])
);

assert($decision->denied());
assert($decision->code() === 'tenant.denied');
```

### Test field filtering

```php
$filtered = $kernel->authorizationRegistry()->filterReadableFields(
    'students.read',
    $request,
    [
        'id' => 1,
        'name' => 'Anil',
        'email' => 'anil@example.com',
        'medical_notes' => 'Hidden',
    ]
);

assert(!array_key_exists('medical_notes', $filtered));
```

---

## 24. CLI and Diagnostics

Authorization is primarily used through code and middleware. Related general commands are useful during verification:

```bash
php bin/mnb-secure config:validate
php bin/mnb-secure vulnerabilities:report
php bin/mnb-secure production:readiness
```

If your build includes policy explanation commands, use them to inspect authorization readiness. Otherwise, use:

```php
print_r($kernel->authorizationRegistry()->explain('students.read'));
```

---

## 25. Production Checklist

Before production, confirm:

```text
Authorization is enabled.
Deny-by-default is enabled.
Denial auditing is enabled.
Public denial reasons are hidden.
Every protected route has an authorization policy.
Every sensitive policy has tenant_required where needed.
Every sensitive policy includes required permissions/scopes.
Every destructive action is limited to strong roles/permissions.
Every high-risk policy has audit enabled.
Field-level read/write rules are configured for sensitive resources.
Resource resolvers fetch tenant ownership fields before allowing access.
SecureDatabase policies match authorization policies.
Role/permission changes trigger token/session revocation where required.
Background jobs preserve actor/tenant authorization context.
Tests cover allow, deny, tenant-deny, field-filter, and policy-missing cases.
```

---

## 26. Common Mistakes

### Mistake 1: Authentication without authorization

Bad:

```text
Route checks that user is logged in, then returns any student ID.
```

Good:

```text
Route authenticates user, checks students.read policy, resolves student tenant ownership, then returns filtered fields.
```

### Mistake 2: Role-only checks

Bad:

```php
if ($user->role === 'admin') {
    deleteStudent($id);
}
```

Good:

```php
$decision = $authorization->decide('students.delete', ...);
```

### Mistake 3: Missing resource ownership check

Bad:

```text
User has student.view, so any student ID is allowed.
```

Good:

```text
User has student.view and the student record belongs to the same school/branch/year.
```

### Mistake 4: Returning all fields after authorization

Bad:

```php
return $studentRecord;
```

Good:

```php
return $authorization->filterReadableFields('students.read', $request, $studentRecord);
```

### Mistake 5: Exposing denial details publicly

Bad:

```json
{"message":"resource does not belong to tenant context"}
```

Good:

```json
{"message":"Access denied","code":"authorization_denied"}
```

---

## 27. Recommended Implementation Pattern

For every protected endpoint:

```text
1. Define authentication strategy.
2. Define authorization policy.
3. Define trust boundary if data crosses zones.
4. Define tenant ownership resolver for object-level routes.
5. Define database table policy.
6. Filter response fields.
7. Audit sensitive allow/deny decisions.
8. Add tests for allowed, denied, cross-tenant, and field-filter behavior.
```

Example protected route flow:

```php
$pipeline = new MiddlewarePipeline([
    $kernel->requestTrustMiddleware(),
    $kernel->secureRequestMiddleware('authenticated'),
    $kernel->authenticationMiddleware('api_bearer'),
    $kernel->authorizationMiddleware(
        'students.read',
        new StudentResourceResolver(),
        'read',
        'students',
        'sensitive'
    ),
]);
```

This gives a consistent route security model instead of controller-by-controller security decisions.

---

## 28. Summary

The **Authorization Strategy** provides policy-driven access control for `mnb-secure-core`.

It protects against:

```text
Broken access control
IDOR
Cross-tenant access
Role bypass
Permission mismatch
Sensitive field exposure
Unsafe writes
Policy gaps
Trust-boundary bypass
```

Use it with:

```text
Authentication Strategy
Trust Zones and Data Boundaries
Secure Request Receiving Strategy
Secure Database Governance
Token Revocation and Session Control
Safe Error Responses
Security Audit Trail
```

Best practice:

```text
Authenticate first.
Authorize every protected action.
Resolve the target resource.
Check tenant ownership.
Filter fields.
Audit sensitive decisions.
Deny by default.
```
