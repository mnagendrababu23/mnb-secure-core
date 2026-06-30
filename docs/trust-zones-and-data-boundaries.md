# Trust Zones and Data Boundaries

**Package:** `mnb/mnb-secure-core`  
**Release line:** `MNB Secure Core v1.0.1`  
**Document type:** Detailed feature documentation and code usage  
**Feature area:** Trust boundary, data classification, tenant isolation, field filtering, access decisions, audit trail

---

## 1. Overview

The **Trust Zones and Data Boundaries** engine helps an application decide whether a user, service, tenant, or internal system is allowed to access a specific class of data for a specific action.

It answers questions like:

```text
Can a public user read this data?
Can an authenticated user see this internal field?
Can a school admin update this student record?
Can a super admin delete this sensitive resource?
Can an internal system access highly sensitive backup data?
Does this record belong to the current tenant context?
Which fields should be removed before returning the response?
Should this boundary decision be audited?
```

This engine is the first layer of safe application design. It defines **who is operating**, **where they are operating from**, **what data they are touching**, and **which boundary rules must apply** before other engines such as authorization, database governance, file security, token/session control, and audit logging are used.

---

## 2. Why Trust Zones Matter

Most security problems happen when an application treats all requests as equal. A public visitor, logged-in user, school administrator, super administrator, and internal background job should not share the same data access boundary.

Trust zones help you separate these actors clearly:

```text
Public internet user
    ↓
Authenticated user
    ↓
School / tenant admin
    ↓
Super admin
    ↓
Internal system / trusted background process
```

A data boundary then decides what each zone can do with each data class.

Example:

```text
Public user          → can read public pages only
Authenticated user   → can read internal own-profile data
School admin         → can read/update sensitive student data inside own school
Super admin          → can perform high-level admin operations
Internal system      → can run backup or internal maintenance workflows
```

---

## 3. Main Classes

The trust boundary engine is mainly built around these classes:

```text
Mnb\SecurityCore\Trust\TrustZone
Mnb\SecurityCore\Trust\DataBoundary
Mnb\SecurityCore\Trust\BoundaryGuard
Mnb\SecurityCore\Trust\TrustZoneResolver
Mnb\SecurityCore\Trust\TrustBoundaryPolicy
Mnb\SecurityCore\Trust\TrustBoundaryRegistry
Mnb\SecurityCore\Trust\TrustBoundaryContext
Mnb\SecurityCore\Trust\TrustBoundaryDecision
Mnb\SecurityCore\Http\Middleware\TrustBoundaryMiddleware
Mnb\SecurityCore\Http\Middleware\TenantBoundaryMiddleware
Mnb\SecurityCore\Authz\TenantContext
Mnb\SecurityCore\Authz\TenantGuard
Mnb\SecurityCore\Data\DataClassifier
```

The central access point is usually:

```php
$kernel->trustBoundaryRegistry();
$kernel->trustBoundaryPolicy('students.read');
$kernel->trustBoundaryMiddleware('students.read');
$kernel->trustZoneResolver();
```

---

## 4. Installation

Install the package from Packagist:

```bash
composer require mnb/mnb-secure-core
```

Basic bootstrap:

```php
<?php

require __DIR__ . '/vendor/autoload.php';

use Mnb\SecurityCore\Core\SecurityKernel;
use Mnb\SecurityCore\Env\EnvLoader;

EnvLoader::load(__DIR__ . '/.env');

$config = require __DIR__ . '/config/security.php';
$kernel = new SecurityKernel($config);
```

---

## 5. Trust Zones

The default trust zones are defined by `TrustZone`:

```php
use Mnb\SecurityCore\Trust\TrustZone;

TrustZone::PUBLIC;
TrustZone::AUTHENTICATED;
TrustZone::SCHOOL_ADMIN;
TrustZone::SUPER_ADMIN;
TrustZone::INTERNAL_SYSTEM;
```

Default zone meanings:

| Zone | Meaning | Example actor |
| --- | --- | --- |
| `public` | Unknown or unauthenticated caller | Visitor, crawler, public page request |
| `authenticated` | Logged-in user with normal access | Student, parent, staff user |
| `school_admin` | Tenant-level admin | School admin, branch admin |
| `super_admin` | Global privileged admin | Platform owner, root admin |
| `internal_system` | Trusted internal service | Queue worker, backup job, internal scheduler |

You can validate a zone:

```php
use Mnb\SecurityCore\Trust\TrustZone;

if (!TrustZone::isValid($zone)) {
    throw new InvalidArgumentException('Unknown trust zone.');
}
```

---

## 6. Data Classes

Data classes are defined by `DataClassifier`:

```php
use Mnb\SecurityCore\Data\DataClassifier;

DataClassifier::PUBLIC;
DataClassifier::INTERNAL;
DataClassifier::CONFIDENTIAL;
DataClassifier::SENSITIVE;
DataClassifier::HIGHLY_SENSITIVE;
```

Recommended meaning:

| Data class | Meaning | Examples |
| --- | --- | --- |
| `public` | Safe for public users | Blog title, public page slug, public notice |
| `internal` | Normal authenticated/internal app data | Record ID, display name, non-sensitive status |
| `confidential` | Private but not extreme-risk data | Email, internal notes, non-public reports |
| `sensitive` | Regulated, personal, or risky data | Phone, student records, financial data |
| `highly_sensitive` | Data requiring strongest control | Password hashes, secrets, backups, private keys |

Classify fields manually:

```php
use Mnb\SecurityCore\Data\DataClassifier;

$classifier = new DataClassifier([
    'id' => DataClassifier::INTERNAL,
    'name' => DataClassifier::INTERNAL,
    'email' => DataClassifier::CONFIDENTIAL,
    'parent_phone' => DataClassifier::SENSITIVE,
    'password_hash' => DataClassifier::HIGHLY_SENSITIVE,
]);

echo $classifier->classify('parent_phone'); // sensitive
```

Check whether a field is sensitive:

```php
if ($classifier->isSensitive('parent_phone')) {
    // apply masking, boundary checks, or stronger audit
}
```

---

## 7. Simple Boundary Guard Usage

For simple applications, you can use `BoundaryGuard` and `DataBoundary` directly.

```php
<?php

use Mnb\SecurityCore\Data\DataClassifier;
use Mnb\SecurityCore\Trust\BoundaryGuard;
use Mnb\SecurityCore\Trust\DataBoundary;
use Mnb\SecurityCore\Trust\TrustZone;

$guard = new BoundaryGuard();

$guard->add(new DataBoundary(
    TrustZone::PUBLIC,
    [DataClassifier::PUBLIC],
    ['read']
));

$guard->add(new DataBoundary(
    TrustZone::AUTHENTICATED,
    [DataClassifier::PUBLIC, DataClassifier::INTERNAL, DataClassifier::CONFIDENTIAL],
    ['read']
));

$guard->add(new DataBoundary(
    TrustZone::SCHOOL_ADMIN,
    [DataClassifier::PUBLIC, DataClassifier::INTERNAL, DataClassifier::CONFIDENTIAL, DataClassifier::SENSITIVE],
    ['read', 'create', 'update']
));

$guard->add(new DataBoundary(
    TrustZone::INTERNAL_SYSTEM,
    [
        DataClassifier::PUBLIC,
        DataClassifier::INTERNAL,
        DataClassifier::CONFIDENTIAL,
        DataClassifier::SENSITIVE,
        DataClassifier::HIGHLY_SENSITIVE,
    ],
    ['read', 'create', 'update', 'backup']
));

$canPublicReadSensitive = $guard->allows(
    TrustZone::PUBLIC,
    DataClassifier::SENSITIVE,
    'read'
);

$canInternalRunBackup = $guard->allows(
    TrustZone::INTERNAL_SYSTEM,
    DataClassifier::HIGHLY_SENSITIVE,
    'backup'
);
```

Expected result:

```text
Public reading sensitive data      → denied
Internal system running backup     → allowed
School admin updating sensitive    → allowed
School admin running backup        → denied
```

Use direct `BoundaryGuard` for small apps, quick utilities, or unit tests. Use `TrustBoundaryRegistry` for production applications.

---

## 8. Recommended Configuration

The production-friendly approach is to define trust boundaries in `config/security.php`.

```php
return [
    'trust_boundaries' => [
        'enabled' => true,
        'hide_denial_reasons' => true,
        'deny_unclassified_fields' => true,

        'zones' => [
            'public',
            'authenticated',
            'school_admin',
            'super_admin',
            'internal_system',
        ],

        'zone_data_access' => [
            'public' => ['public'],
            'authenticated' => ['public', 'internal'],
            'school_admin' => ['public', 'internal', 'confidential', 'sensitive'],
            'super_admin' => ['public', 'internal', 'confidential', 'sensitive'],
            'internal_system' => ['public', 'internal', 'confidential', 'sensitive', 'highly_sensitive'],
        ],

        'zone_resolvers' => [
            'school_admin' => [
                'roles' => ['school_admin', 'admin'],
                'scopes' => ['school:*'],
                'permissions' => ['school.manage', 'student.manage'],
            ],
            'super_admin' => [
                'roles' => ['super_admin', 'root', 'owner'],
                'scopes' => ['admin:*', '*'],
            ],
            'internal_system' => [
                'roles' => ['internal_system', 'system'],
                'scopes' => ['system:*', 'internal:*'],
            ],
        ],

        'resources' => [
            'students' => [
                'data_class' => 'sensitive',
                'tenant_scoped' => true,
                'fields' => [
                    'id' => 'internal',
                    'name' => 'internal',
                    'email' => 'confidential',
                    'parent_phone' => 'sensitive',
                    'school_id' => 'internal',
                    'branch_id' => 'internal',
                    'password_hash' => 'highly_sensitive',
                ],
            ],
            'public_pages' => [
                'data_class' => 'public',
                'tenant_scoped' => false,
                'fields' => [
                    'title' => 'public',
                    'slug' => 'public',
                    'body' => 'public',
                ],
            ],
        ],

        'rules' => [
            'public.read' => [
                'zones' => ['public', 'authenticated', 'school_admin', 'super_admin'],
                'data_classes' => ['public'],
                'actions' => ['read'],
                'resources' => ['public_pages'],
                'audit' => false,
            ],

            'students.read' => [
                'zones' => ['school_admin', 'super_admin'],
                'data_classes' => ['internal', 'confidential', 'sensitive'],
                'actions' => ['read'],
                'resources' => ['students'],
                'permissions' => ['student.view'],
                'tenant_required' => true,
                'audit' => true,
            ],

            'students.update' => [
                'zones' => ['school_admin', 'super_admin'],
                'data_classes' => ['sensitive'],
                'actions' => ['update'],
                'resources' => ['students'],
                'permissions' => ['student.update'],
                'tenant_required' => true,
                'audit' => true,
            ],

            'students.delete' => [
                'zones' => ['super_admin'],
                'data_classes' => ['sensitive'],
                'actions' => ['delete'],
                'resources' => ['students'],
                'permissions' => ['student.delete'],
                'tenant_required' => true,
                'audit' => true,
            ],

            'backup.run' => [
                'zones' => ['internal_system'],
                'data_classes' => ['highly_sensitive'],
                'actions' => ['backup'],
                'scopes' => ['system:backup', 'system:*'],
                'audit' => true,
            ],
        ],
    ],
];
```

---

## 9. Policy Fields

Each trust boundary rule supports the following fields:

| Field | Required | Purpose |
| --- | --- | --- |
| `zones` | Yes | Which trust zones can use this rule |
| `data_classes` | Yes | Which data classes are allowed |
| `actions` | Yes | Allowed actions such as `read`, `create`, `update`, `delete`, `backup` |
| `resources` | No | Resource names such as `students`, `fees`, `users`, `reports` |
| `permissions` | No | Required permissions from authenticated context |
| `scopes` | No | Required API/system scopes |
| `roles` | No | Required user roles |
| `tenant_required` | No | Whether a tenant context must exist and match the resource |
| `audit` | No | Whether allow/deny decisions should be recorded |
| `deny_message` | No | Optional internal denial message |

Production recommendation:

```text
Use explicit zones, data_classes, actions, resources, permissions, and tenant_required.
Avoid wildcards except for carefully reviewed internal policies.
Enable audit for sensitive, highly sensitive, delete, export, backup, and admin actions.
```

---

## 10. Resolving a Trust Zone

`TrustZoneResolver` resolves a zone from the request and authentication context.

```php
use Mnb\SecurityCore\Auth\AuthContext;

$resolver = $kernel->trustZoneResolver();

$auth = new AuthContext(
    true,
    15,
    ['school:*'],
    ['student.view'],
    ['school_admin']
);

$zone = $resolver->resolve(null, $auth);

// $zone === 'school_admin'
```

Default resolution order:

```text
1. Explicit request attribute `trust_zone`, if valid
2. Unauthenticated actor → public
3. Internal system role/scope → internal_system
4. Super admin role/scope → super_admin
5. School admin role/scope/permission → school_admin
6. Otherwise authenticated → authenticated
```

---

## 11. Making Boundary Decisions

Use `TrustBoundaryRegistry` to evaluate a configured policy.

```php
use Mnb\SecurityCore\Auth\AuthContext;
use Mnb\SecurityCore\Authz\TenantContext;

$registry = $kernel->trustBoundaryRegistry();

$tenant = new TenantContext(
    userId: 15,
    schoolId: 10,
    branchId: 5,
    academicYearId: 2026,
    permissions: ['student.view']
);

$auth = new AuthContext(
    true,
    15,
    ['school:*'],
    ['student.view'],
    ['school_admin']
);

$student = [
    'id' => 44,
    'name' => 'Ravi Kumar',
    'parent_phone' => '9876543210',
    'school_id' => 10,
    'branch_id' => 5,
    'academic_year_id' => 2026,
];

$decision = $registry->decide(
    policyName: 'students.read',
    request: null,
    resource: $student,
    action: 'read',
    dataClass: 'sensitive',
    tenant: $tenant,
    auth: $auth,
    resourceName: 'students'
);

if ($decision->denied()) {
    http_response_code(403);
    echo json_encode([
        'status' => false,
        'message' => 'Access denied.',
    ]);
    exit;
}
```

Inspect the decision:

```php
print_r($decision->toArray());
```

Example allowed result:

```php
[
    'allowed' => true,
    'policy' => 'students.read',
    'zone' => 'school_admin',
    'action' => 'read',
    'data_class' => 'sensitive',
    'resource' => 'students',
    'reason' => 'allowed',
    'audit_required' => true,
]
```

Example denied reasons:

```text
trust boundary policy is not registered
zone is not allowed for this boundary policy
resource is not allowed for this boundary policy
action is not allowed for this boundary policy
data class is not allowed for this boundary policy
required role is missing
required scope is missing
required permission is missing
tenant context is required
resource does not belong to tenant context
```

In production, keep `hide_denial_reasons` enabled when returning responses to frontend users.

---

## 12. Tenant Boundary Usage

`TenantContext` represents the current tenant or school boundary.

```php
use Mnb\SecurityCore\Authz\TenantContext;

$tenant = new TenantContext(
    userId: 15,
    schoolId: 10,
    branchId: 5,
    academicYearId: 2026,
    roles: ['school_admin'],
    permissions: ['student.view'],
    classIds: [1, 2, 3],
    sectionIds: [10, 11]
);
```

Build context from PHP session:

```php
$tenant = TenantContext::fromSession();
```

Use `TenantGuard` directly:

```php
use Mnb\SecurityCore\Authz\TenantGuard;

$guard = new TenantGuard();

$record = [
    'id' => 44,
    'school_id' => 10,
    'branch_id' => 5,
    'academic_year_id' => 2026,
];

if (!$guard->recordBelongsToContext($record, $tenant)) {
    throw new RuntimeException('Tenant boundary violation.');
}
```

Check class/section restrictions:

```php
$student = [
    'id' => 44,
    'class_id' => 2,
    'section_id' => 10,
];

if (!$guard->classSectionAllowed($student, $tenant)) {
    throw new RuntimeException('Class/section access denied.');
}
```

---

## 13. Field Filtering by Zone

A user may be allowed to read a resource, but not every field inside it.

Example student record:

```php
$student = [
    'id' => 44,
    'name' => 'Ravi Kumar',
    'email' => 'ravi@example.test',
    'parent_phone' => '9876543210',
    'password_hash' => '$2y$...',
    'school_id' => 10,
];
```

Filter for public zone:

```php
$public = $registry->filterForZone('students', $student, 'public');
```

Possible result:

```php
[]
```

Because the `students` fields are mostly internal/confidential/sensitive.

Filter for school admin:

```php
$admin = $registry->filterForZone('students', $student, 'school_admin');
```

Possible result:

```php
[
    'id' => 44,
    'name' => 'Ravi Kumar',
    'email' => 'ravi@example.test',
    'parent_phone' => '9876543210',
    'school_id' => 10,
]
```

Notice that `password_hash` is removed because it is `highly_sensitive`, and the default school admin zone does not include `highly_sensitive` field access.

Recommended production setting:

```php
'deny_unclassified_fields' => true,
```

This treats unknown fields as high-risk instead of accidentally public.

---

## 14. Middleware Usage

Use `TrustBoundaryMiddleware` to protect a route or operation.

```php
use Mnb\SecurityCore\Http\Middleware\TrustBoundaryMiddleware;
use Mnb\SecurityCore\Http\MiddlewarePipeline;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;

$studentResolver = function (Request $request): array {
    // Load resource safely from database/service.
    return [
        'id' => 44,
        'school_id' => 10,
        'branch_id' => 5,
        'academic_year_id' => 2026,
    ];
};

$middleware = $kernel->trustBoundaryMiddleware(
    policyName: 'students.read',
    resourceResolver: $studentResolver,
    action: 'read',
    dataClass: 'sensitive',
    resourceName: 'students'
);

$pipeline = new MiddlewarePipeline([$middleware]);

$response = $pipeline->handle($request, function (Request $request): Response {
    return Response::json([
        'status' => true,
        'message' => 'Student access allowed.',
        'zone' => $request->attribute('trust_zone'),
    ]);
});
```

When access is denied, middleware returns a safe `403` JSON response.

When access is allowed, it attaches:

```text
trust_boundary_decision
trust_zone
```

to the request attributes.

---

## 15. Plain PHP Route Example

```php
<?php

require __DIR__ . '/../vendor/autoload.php';

use Mnb\SecurityCore\Core\SecurityKernel;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;
use Mnb\SecurityCore\Auth\AuthContext;
use Mnb\SecurityCore\Authz\TenantContext;

$config = require __DIR__ . '/../config/security.php';
$kernel = new SecurityKernel($config);

$request = Request::fromGlobals();

// In a real app, build these from your auth/session/token layer.
$auth = new AuthContext(
    true,
    15,
    ['school:*'],
    ['student.view'],
    ['school_admin']
);

$tenant = new TenantContext(
    userId: 15,
    schoolId: 10,
    branchId: 5,
    academicYearId: 2026,
    permissions: ['student.view']
);

$student = [
    'id' => 44,
    'name' => 'Ravi Kumar',
    'school_id' => 10,
    'branch_id' => 5,
    'academic_year_id' => 2026,
];

$decision = $kernel->trustBoundaryRegistry()->decide(
    'students.read',
    $request,
    $student,
    'read',
    'sensitive',
    $tenant,
    $auth,
    'students'
);

if ($decision->denied()) {
    Response::json([
        'status' => false,
        'message' => 'Access denied.',
        'request_id' => $request->attribute('request_id'),
    ], 403)->send();
    exit;
}

$safeStudent = $kernel->trustBoundaryRegistry()->filterForZone(
    'students',
    $student,
    $decision->zone()
);

Response::json([
    'status' => true,
    'data' => $safeStudent,
])->send();
```

---

## 16. API Usage Example

For API endpoints, trust boundaries should usually be used after request validation and authentication, but before database updates or response output.

Recommended order:

```text
Request receiving middleware
    ↓
Trusted host / HTTPS / origin middleware
    ↓
Authentication middleware
    ↓
Token/session validation
    ↓
Tenant context creation
    ↓
Trust boundary middleware
    ↓
Authorization middleware
    ↓
Controller/service/database operation
    ↓
Field filtering / masking
    ↓
Safe response
```

Example API flow:

```php
$decision = $kernel->trustBoundaryRegistry()->decide(
    'students.update',
    $request,
    $studentRecord,
    'update',
    'sensitive',
    $tenantContext,
    $authContext,
    'students'
);

if ($decision->denied()) {
    return Response::json([
        'status' => false,
        'message' => 'You are not allowed to update this student.',
    ], 403);
}

// Continue with secure database update.
```

---

## 17. School / Multi-Tenant Example

In school, ERP, CRM, SaaS, and admin-panel systems, a user may have permission to read students, but only inside their own school/tenant.

Rule:

```php
'students.read' => [
    'zones' => ['school_admin', 'super_admin'],
    'data_classes' => ['internal', 'confidential', 'sensitive'],
    'actions' => ['read'],
    'resources' => ['students'],
    'permissions' => ['student.view'],
    'tenant_required' => true,
    'audit' => true,
],
```

Matching record:

```php
$tenant = new TenantContext(userId: 15, schoolId: 10);
$student = ['id' => 44, 'school_id' => 10];

$decision = $registry->decide('students.read', null, $student, 'read', 'sensitive', $tenant, $auth, 'students');

// allowed
```

Cross-tenant record:

```php
$tenant = new TenantContext(userId: 15, schoolId: 10);
$student = ['id' => 45, 'school_id' => 99];

$decision = $registry->decide('students.read', null, $student, 'read', 'sensitive', $tenant, $auth, 'students');

// denied: resource does not belong to tenant context
```

This helps protect against IDOR and tenant leakage.

---

## 18. Admin and Internal System Boundaries

Some actions should never be available to normal authenticated users or tenant admins.

Example: backup job.

```php
'backup.run' => [
    'zones' => ['internal_system'],
    'data_classes' => ['highly_sensitive'],
    'actions' => ['backup'],
    'scopes' => ['system:backup', 'system:*'],
    'audit' => true,
],
```

Internal system auth context:

```php
$auth = new AuthContext(
    true,
    'system-worker-1',
    ['system:*'],
    [],
    ['internal_system']
);

$decision = $registry->decide(
    'backup.run',
    null,
    [],
    'backup',
    'highly_sensitive',
    null,
    $auth,
    'backup'
);
```

This keeps background workers and human users separated.

---

## 19. Auditing Boundary Decisions

When a policy has:

```php
'audit' => true,
```

allowed and denied decisions can be recorded through `SecurityAuditTrail`.

Typical audit event information:

```text
category: trust
action: boundary.allowed / boundary.denied
outcome: success / denied
severity: info / warning
actor: user id and roles when available
target: policy, resource, resource fingerprint
context: IP, method, path, host, zone, action, data class
metadata: denial reason
```

Why this matters:

```text
You can prove who tried to cross which boundary.
You can detect repeated cross-tenant attempts.
You can review sensitive data access.
You can attach trust boundary evidence to security verification reports.
```

---

## 20. Safe Denial Responses

Boundary decisions may include technical reasons, but those reasons should not always be shown to the frontend.

Recommended production setting:

```php
'hide_denial_reasons' => true,
```

Safe response:

```json
{
  "status": false,
  "message": "Access denied."
}
```

Avoid frontend responses like:

```json
{
  "message": "resource does not belong to tenant context"
}
```

That message is useful for internal logs, but it may reveal sensitive information to attackers.

---

## 21. Integration With Authorization Engine

Trust boundaries and authorization are related but not identical.

| Layer | Question answered |
| --- | --- |
| Trust boundary | Is this zone/data/action/resource boundary allowed? |
| Authorization | Does this actor have the required permission, role, scope, ownership, and field access? |
| Tenant guard | Does this resource belong to the current tenant context? |
| Database governance | Can this query/update/delete be performed safely? |
| Output filtering | Which fields may be returned to this zone? |

Recommended flow:

```text
Resolve actor
Resolve trust zone
Validate trust boundary
Validate authorization policy
Apply tenant-scoped database query
Filter/mask response fields
Audit sensitive decisions
```

---

## 22. Integration With Database Governance

Trust boundaries should be reflected in database policies.

Example:

```text
Trust boundary says: school admin can read sensitive student data inside own tenant.
Database policy should also enforce: SELECT only allowed columns, WHERE school_id = tenant school id, no password_hash column.
```

Recommended service pattern:

```php
$decision = $registry->decide('students.read', $request, $student, 'read', 'sensitive', $tenant, $auth, 'students');

if ($decision->denied()) {
    return Response::json(['status' => false, 'message' => 'Access denied.'], 403);
}

// Then use SecureDatabase with a table policy and tenant context.
```

Never rely on frontend filtering alone. Always enforce tenant and boundary rules before database writes, deletes, exports, or downloads.

---

## 23. Integration With File Security

For files and documents, map each file to a resource and data class.

Example:

```php
'files.download' => [
    'zones' => ['school_admin', 'super_admin'],
    'data_classes' => ['confidential', 'sensitive'],
    'actions' => ['download'],
    'resources' => ['student_documents'],
    'permissions' => ['student.document.download'],
    'tenant_required' => true,
    'audit' => true,
],
```

Before serving a protected file:

```php
$decision = $registry->decide(
    'files.download',
    $request,
    $documentRecord,
    'download',
    'sensitive',
    $tenant,
    $auth,
    'student_documents'
);

if ($decision->denied()) {
    return Response::json(['status' => false, 'message' => 'Access denied.'], 403);
}

// Continue with ProtectedDownloadManager.
```

---

## 24. Integration With Queue and Background Jobs

Background jobs must not automatically be treated as super admin.

Use a separate zone:

```text
internal_system
```

Queue job handlers should receive a safe job context and then evaluate the correct boundary.

Example:

```php
$auth = new AuthContext(
    true,
    'queue-worker',
    ['system:*'],
    [],
    ['internal_system']
);

$decision = $registry->decide(
    'backup.run',
    null,
    [],
    'backup',
    'highly_sensitive',
    null,
    $auth,
    'backup'
);
```

For user-requested jobs such as exports, store the original user/tenant context and re-check boundaries before processing.

---

## 25. Common Boundary Rule Examples

### 25.1 Public page read

```php
'public_pages.read' => [
    'zones' => ['public', 'authenticated', 'school_admin', 'super_admin'],
    'data_classes' => ['public'],
    'actions' => ['read'],
    'resources' => ['public_pages'],
    'audit' => false,
],
```

### 25.2 Student read

```php
'students.read' => [
    'zones' => ['school_admin', 'super_admin'],
    'data_classes' => ['internal', 'confidential', 'sensitive'],
    'actions' => ['read'],
    'resources' => ['students'],
    'permissions' => ['student.view'],
    'tenant_required' => true,
    'audit' => true,
],
```

### 25.3 Student update

```php
'students.update' => [
    'zones' => ['school_admin', 'super_admin'],
    'data_classes' => ['sensitive'],
    'actions' => ['update'],
    'resources' => ['students'],
    'permissions' => ['student.update'],
    'tenant_required' => true,
    'audit' => true,
],
```

### 25.4 Sensitive export

```php
'students.export' => [
    'zones' => ['super_admin'],
    'data_classes' => ['sensitive'],
    'actions' => ['export'],
    'resources' => ['students'],
    'permissions' => ['student.export'],
    'tenant_required' => true,
    'audit' => true,
],
```

### 25.5 Backup run

```php
'backup.run' => [
    'zones' => ['internal_system'],
    'data_classes' => ['highly_sensitive'],
    'actions' => ['backup'],
    'scopes' => ['system:backup', 'system:*'],
    'audit' => true,
],
```

---

## 26. Security Best Practices

### 26.1 Deny unknown fields

Use:

```php
'deny_unclassified_fields' => true,
```

This prevents new fields from accidentally becoming visible.

### 26.2 Keep public zone minimal

Public zone should normally only access:

```text
public data + read action
```

### 26.3 Avoid broad wildcards

Avoid this in production unless carefully reviewed:

```php
'zones' => ['*'],
'data_classes' => ['*'],
'actions' => ['*'],
```

### 26.4 Tenant-scope all tenant resources

For SaaS/school/admin systems, use:

```php
'tenant_required' => true,
```

for every tenant-owned resource.

### 26.5 Audit sensitive and destructive actions

Enable audit for:

```text
sensitive read
create/update/delete
export
download
backup
schema change
admin action
internal system action
```

### 26.6 Never expose technical denial reasons publicly

Use generic frontend messages. Keep specific reasons in protected logs.

---

## 27. Testing Boundary Rules

Test allowed access:

```php
$decision = $registry->decide('students.read', null, $student, 'read', 'sensitive', $tenant, $auth, 'students');
assert($decision->allowed());
```

Test missing permission:

```php
$authWithoutPermission = new AuthContext(true, 15, [], [], ['school_admin']);

$decision = $registry->decide(
    'students.read',
    null,
    $student,
    'read',
    'sensitive',
    $tenant,
    $authWithoutPermission,
    'students'
);

assert($decision->denied());
assert($decision->reason() === 'required permission is missing');
```

Test cross-tenant denial:

```php
$otherTenantStudent = ['id' => 45, 'school_id' => 99];

$decision = $registry->decide(
    'students.read',
    null,
    $otherTenantStudent,
    'read',
    'sensitive',
    $tenant,
    $auth,
    'students'
);

assert($decision->denied());
```

Test field filtering:

```php
$filtered = $registry->filterForZone('students', [
    'name' => 'Ravi',
    'parent_phone' => '9876543210',
    'password_hash' => 'hash',
], 'school_admin');

assert(isset($filtered['name']));
assert(isset($filtered['parent_phone']));
assert(!isset($filtered['password_hash']));
```

---

## 28. CLI and Demo

Run config validation:

```bash
php vendor/mnb/mnb-secure-core/bin/mnb-secure config:validate
```

Run vulnerability matrix report:

```bash
php vendor/mnb/mnb-secure-core/bin/mnb-secure vulnerabilities:report
```

Run demos from the package source checkout:

```bash
php demos/01-trust-zones-data-boundaries.php
php demos/19-trust-zone-boundary-engine.php
```

If installed through Composer, demo files may not be copied into your application unless you copy them from the package.

---

## 29. Production Checklist

Before production, verify:

```text
[ ] trust_boundaries.enabled is true
[ ] hide_denial_reasons is true
[ ] deny_unclassified_fields is true
[ ] public zone only reads public data
[ ] sensitive resources use tenant_required true
[ ] delete/export/download/backup actions use audit true
[ ] every tenant-owned table has tenant fields
[ ] every resource has field classification
[ ] password/token/secret fields are highly_sensitive
[ ] every route has clear resource/action/data class mapping
[ ] cross-tenant tests exist
[ ] field filtering tests exist
[ ] denial reasons are not shown to frontend users
[ ] audit storage is protected and outside public web root
```

---

## 30. Common Mistakes

### Mistake 1: Permission check without tenant boundary

Bad:

```php
if ($auth->can('student.view')) {
    return $student;
}
```

Good:

```php
$decision = $registry->decide('students.read', null, $student, 'read', 'sensitive', $tenant, $auth, 'students');
```

### Mistake 2: Returning full database record

Bad:

```php
return Response::json(['data' => $student]);
```

Good:

```php
$safeStudent = $registry->filterForZone('students', $student, $decision->zone());
return Response::json(['data' => $safeStudent]);
```

### Mistake 3: Treating background jobs as root

Bad:

```text
All workers can access all data.
```

Good:

```text
Workers use internal_system zone and explicit scopes/policies.
```

### Mistake 4: Exposing denial reason to attackers

Bad:

```json
{"message":"resource does not belong to tenant context"}
```

Good:

```json
{"message":"Access denied."}
```

---

## 31. Recommended Naming Conventions

Policy names:

```text
resource.action
students.read
students.update
students.delete
students.export
files.download
backup.run
```

Resource names:

```text
plural lowercase snake_case
students
student_documents
public_pages
fee_payments
audit_logs
```

Actions:

```text
read
create
update
delete
restore
export
download
upload
approve
backup
```

Data classes:

```text
public
internal
confidential
sensitive
highly_sensitive
```

---

## 32. Minimal Working Example

```php
<?php

require __DIR__ . '/vendor/autoload.php';

use Mnb\SecurityCore\Auth\AuthContext;
use Mnb\SecurityCore\Authz\TenantContext;
use Mnb\SecurityCore\Core\SecurityKernel;

$config = require __DIR__ . '/config/security.php';
$kernel = new SecurityKernel($config);

$registry = $kernel->trustBoundaryRegistry();

$auth = new AuthContext(
    true,
    15,
    ['school:*'],
    ['student.view'],
    ['school_admin']
);

$tenant = new TenantContext(
    userId: 15,
    schoolId: 10,
    branchId: 5,
    academicYearId: 2026
);

$student = [
    'id' => 44,
    'name' => 'Ravi Kumar',
    'parent_phone' => '9876543210',
    'password_hash' => 'hidden-hash',
    'school_id' => 10,
    'branch_id' => 5,
    'academic_year_id' => 2026,
];

$decision = $registry->decide(
    'students.read',
    null,
    $student,
    'read',
    'sensitive',
    $tenant,
    $auth,
    'students'
);

if ($decision->denied()) {
    echo json_encode([
        'status' => false,
        'message' => 'Access denied.',
    ]);
    exit;
}

$safeData = $registry->filterForZone('students', $student, $decision->zone());

echo json_encode([
    'status' => true,
    'zone' => $decision->zone(),
    'data' => $safeData,
]);
```

---

## 33. Summary

The **Trust Zones and Data Boundaries** engine provides a structured way to protect sensitive application data before it reaches database operations, file downloads, exports, background jobs, or frontend responses.

Use it to enforce:

```text
Trust zone separation
Data classification
Tenant isolation
Permission/scope/role requirements
Field-level response filtering
Safe denial responses
Audit-ready boundary decisions
```

For production applications, every sensitive resource should have:

```text
A resource definition
Field classifications
At least one explicit boundary rule
Tenant requirements where needed
Audit enabled for sensitive/destructive actions
Tests for allow, deny, cross-tenant, and field filtering behavior
```
