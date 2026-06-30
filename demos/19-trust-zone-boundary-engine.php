<?php
require_once __DIR__ . '/_demo_bootstrap.php';

use Mnb\SecurityCore\Auth\AuthContext;
use Mnb\SecurityCore\Authz\TenantContext;
use Mnb\SecurityCore\Http\Middleware\TrustBoundaryMiddleware;
use Mnb\SecurityCore\Http\MiddlewarePipeline;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;
use Mnb\SecurityCore\Logging\SecurityAuditTrail;
use Mnb\SecurityCore\Logging\TamperEvidentAuditLogger;
use Mnb\SecurityCore\Trust\TrustBoundaryRegistry;
use Mnb\SecurityCore\Trust\TrustZone;

demo_title('19. Trust Zone Boundary Engine');

$config = [
    'trust_boundaries' => [
        'enabled' => true,
        'hide_denial_reasons' => false,
        'deny_unclassified_fields' => true,
        'resources' => [
            'students' => [
                'data_class' => 'sensitive',
                'tenant_scoped' => true,
                'fields' => [
                    'id' => 'internal',
                    'name' => 'internal',
                    'parent_phone' => 'sensitive',
                    'password_hash' => 'highly_sensitive',
                    'school_id' => 'internal',
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
            'students.delete' => [
                'zones' => ['super_admin'],
                'data_classes' => ['sensitive'],
                'actions' => ['delete'],
                'resources' => ['students'],
                'permissions' => ['student.delete'],
                'tenant_required' => true,
                'audit' => true,
            ],
        ],
    ],
];

$auditFile = demo_storage_path('audit/trust-boundary-demo.log');
@unlink($auditFile);
$audit = new SecurityAuditTrail(new TamperEvidentAuditLogger($auditFile));
$registry = TrustBoundaryRegistry::fromConfig($config, $audit);

$tenant = new TenantContext(userId: 15, schoolId: 10, branchId: 5, academicYearId: 2026, permissions: ['student.view']);
$request = (new Request('GET', '/students/44', [], [], [], ['REMOTE_ADDR' => '127.0.0.1']))
    ->withAttribute('auth', new AuthContext(true, 15, ['school:*'], ['student.view'], ['school_admin']))
    ->withAttribute('tenant_context', $tenant);

$student = ['id' => 44, 'name' => 'Ravi Kumar', 'parent_phone' => '9876543210', 'password_hash' => 'hash', 'school_id' => 10];
$otherSchoolStudent = ['id' => 45, 'name' => 'Other Student', 'school_id' => 99];

$readDecision = $registry->decide('students.read', $request, $student, 'read', 'sensitive', resourceName: 'students');
$deleteDecision = $registry->decide('students.delete', $request, $student, 'delete', 'sensitive', resourceName: 'students');
$crossTenantDecision = $registry->decide('students.read', $request, $otherSchoolStudent, 'read', 'sensitive', resourceName: 'students');
$filteredPublic = $registry->filterForZone('students', $student, TrustZone::PUBLIC);
$filteredAdmin = $registry->filterForZone('students', $student, TrustZone::SCHOOL_ADMIN);

$middleware = new TrustBoundaryMiddleware($registry, 'students.read', fn() => $student, action: 'read', dataClass: 'sensitive', resourceName: 'students', hideReason: false);
$response = (new MiddlewarePipeline([$middleware]))->handle($request, fn(Request $request) => Response::json([
    'status' => true,
    'zone' => $request->attribute('trust_zone'),
]));

demo_step('Read decision', $readDecision->toArray());
demo_step('Delete decision allowed', $deleteDecision->allowed());
demo_step('Cross-tenant decision reason', $crossTenantDecision->reason());
demo_step('Public filtered record', $filteredPublic);
demo_step('Admin filtered record', $filteredAdmin);
demo_step('Middleware response status', $response->status());
demo_step('Audit entries', count((new TamperEvidentAuditLogger($auditFile))->read(null, 'trust')));

demo_result(
    $readDecision->allowed()
    && $deleteDecision->denied()
    && $crossTenantDecision->denied()
    && !isset($filteredPublic['parent_phone'])
    && isset($filteredAdmin['parent_phone'])
    && !isset($filteredAdmin['password_hash'])
    && $response->status() === 200,
    'Trust boundary engine resolves zones, enforces tenant/data/action rules, filters fields, and audits decisions.',
    'Trust boundary engine did not enforce expected rules.'
);
