<?php
require_once __DIR__ . '/_demo_bootstrap.php';

use Mnb\SecurityCore\Auth\AuthContext;
use Mnb\SecurityCore\Authz\TenantContext;
use Mnb\SecurityCore\Authorization\AuthorizationRegistry;
use Mnb\SecurityCore\Http\Middleware\AuthorizationMiddleware;
use Mnb\SecurityCore\Http\MiddlewarePipeline;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;
use Mnb\SecurityCore\Logging\SecurityAuditTrail;
use Mnb\SecurityCore\Logging\TamperEvidentAuditLogger;
use Mnb\SecurityCore\Trust\TrustBoundaryRegistry;

$trustConfig = [
    'trust_boundaries' => [
        'hide_denial_reasons' => false,
        'resources' => [
            'students' => [
                'data_class' => 'sensitive',
                'tenant_scoped' => true,
                'fields' => [
                    'id' => 'internal',
                    'name' => 'internal',
                    'parent_phone' => 'sensitive',
                    'school_id' => 'internal',
                    'password_hash' => 'highly_sensitive',
                ],
            ],
        ],
        'rules' => [
            'students.read' => [
                'zones' => ['school_admin', 'super_admin'],
                'data_classes' => ['sensitive'],
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
        ],
    ],
];

$audit = new SecurityAuditTrail(new TamperEvidentAuditLogger(demo_storage_path('audit/authorization-engine.log')));
$trust = TrustBoundaryRegistry::fromConfig($trustConfig, $audit);
$authorization = new AuthorizationRegistry([
    'students.read' => [
        'resource' => 'students',
        'actions' => ['read'],
        'roles' => ['school_admin', 'super_admin'],
        'permissions' => ['student.view'],
        'scopes' => ['students:read'],
        'tenant_required' => true,
        'data_classes' => ['sensitive'],
        'trust_boundary' => 'students.read',
        'audit' => true,
        'fields' => [
            'read' => [
                'school_admin' => ['id', 'name', 'parent_phone', 'school_id'],
                'super_admin' => ['*'],
            ],
        ],
    ],
    'students.update' => [
        'resource' => 'students',
        'actions' => ['update'],
        'roles' => ['school_admin', 'super_admin'],
        'permissions' => ['student.update'],
        'scopes' => ['students:update'],
        'tenant_required' => true,
        'data_classes' => ['sensitive'],
        'trust_boundary' => 'students.update',
        'audit' => true,
        'fields' => [
            'write' => [
                'school_admin' => ['name', 'parent_phone'],
                'super_admin' => ['*'],
            ],
        ],
    ],
], ['deny_by_default' => true, 'audit_denials' => true, 'hide_denial_reasons' => false], $audit, $trust);

$request = (new Request('PATCH', '/api/students/44', [], [], [], ['REMOTE_ADDR' => '127.0.0.1']))
    ->withAttribute('auth', new AuthContext(true, 25, ['students:read', 'students:update', 'school:*'], ['student.view', 'student.update'], ['school_admin']))
    ->withAttribute('tenant_context', new TenantContext(userId: 25, schoolId: 10, branchId: 5, academicYearId: 2026, permissions: ['student.view', 'student.update']));

$student = ['id' => 44, 'name' => 'Ravi Kumar', 'parent_phone' => '9876543210', 'school_id' => 10, 'password_hash' => 'hash'];
$otherSchoolStudent = ['id' => 45, 'name' => 'Cross Tenant', 'parent_phone' => '9999999999', 'school_id' => 99, 'password_hash' => 'hash'];

$readDecision = $authorization->decide('students.read', $request, $student, 'read', 'students', 'sensitive');
$crossTenantDecision = $authorization->decide('students.read', $request, $otherSchoolStudent, 'read', 'students', 'sensitive');
$readable = $authorization->filterReadableFields('students.read', $request, $student);
$writable = $authorization->filterWritableFields('students.update', $request, ['name' => 'Ravi Updated', 'parent_phone' => '9000000000', 'school_id' => 99, 'password_hash' => 'evil']);

$middleware = new AuthorizationMiddleware($authorization, 'students.update', fn(Request $request): array => ['id' => 44, 'school_id' => 10], action: 'update', resourceName: 'students', dataClass: 'sensitive', hideReason: false);
$response = (new MiddlewarePipeline([$middleware]))->handle($request, fn(Request $request) => Response::json(['allowed' => $request->attribute('authorization_decision')->allowed()]));

$entries = (new TamperEvidentAuditLogger(demo_storage_path('audit/authorization-engine.log')))->read(null, 'authorization');

demo_title('22. Authorization Strategy Engine');
demo_step('Read decision', $readDecision->toArray());
demo_step('Cross-tenant decision', $crossTenantDecision->toArray());
demo_step('Readable fields', $readable);
demo_step('Writable fields', $writable);
demo_step('Middleware status', $response->status());
demo_step('Audit entries', count($entries));

demo_result(
    $readDecision->allowed()
    && $crossTenantDecision->denied()
    && isset($readable['parent_phone'])
    && !isset($readable['password_hash'])
    && isset($writable['name'])
    && !isset($writable['school_id'])
    && $response->status() === 200
    && count($entries) >= 2,
    'Authorization engine unifies RBAC/scopes/permissions, tenant scope, trust boundaries, field filtering, middleware, and audit decisions.'
);
