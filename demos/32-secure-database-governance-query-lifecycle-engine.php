<?php
require_once __DIR__ . '/_demo_bootstrap.php';

use Mnb\SecurityCore\Authz\Policies\DatabaseResourcePolicy;
use Mnb\SecurityCore\Authz\PolicyRegistry;
use Mnb\SecurityCore\Authz\TenantContext;
use Mnb\SecurityCore\Database\DatabaseHealthChecker;
use Mnb\SecurityCore\Database\DatabasePolicyRegistry;
use Mnb\SecurityCore\Database\DatabasePrivilegeInspector;
use Mnb\SecurityCore\Database\DatabaseResultFilter;
use Mnb\SecurityCore\Database\DryRunDatabaseConnection;
use Mnb\SecurityCore\Database\QueryComplexityGuard;
use Mnb\SecurityCore\Database\QueryCostPolicy;
use Mnb\SecurityCore\Database\RawQueryGuard;
use Mnb\SecurityCore\Database\SchemaChangePolicy;
use Mnb\SecurityCore\Database\SchemaMigrationGuard;
use Mnb\SecurityCore\Database\SecureDatabase;
use Mnb\SecurityCore\Database\SecureQueryBuilder;
use Mnb\SecurityCore\Database\TableSecurityPolicy;
use Mnb\SecurityCore\Logging\TamperEvidentAuditLogger;

demo_title('32. Secure Database Governance and Query Lifecycle Engine');

$config = require __DIR__ . '/../config/security.php';
$costPolicy = new QueryCostPolicy(maxLimit: 100, defaultLimit: 25, maxOffset: 1000, maxSearchLength: 50, maxFilterCount: 5, blockLeadingWildcard: true, slowQueryMs: 500);
$queryGuard = new QueryComplexityGuard($costPolicy);

$studentPolicy = new TableSecurityPolicy(
    table: 'students',
    resourceType: 'student',
    selectableColumns: ['id', 'admission_no', 'first_name', 'last_name', 'email', 'phone', 'status', 'class_id', 'created_at'],
    insertableColumns: ['admission_no', 'first_name', 'last_name', 'email', 'phone', 'status', 'class_id'],
    updatableColumns: ['first_name', 'last_name', 'email', 'phone', 'status', 'class_id'],
    searchableColumns: ['admission_no', 'first_name', 'last_name', 'email'],
    orderableColumns: ['id', 'first_name', 'created_at'],
    sensitiveColumns: ['email', 'phone'],
    hiddenColumns: ['password_hash'],
    maskedColumns: ['email', 'phone']
);

$dbPolicies = new DatabasePolicyRegistry(['students' => $studentPolicy]);
demo_step('Policy registry has students policy', $dbPolicies->has('students'));

$authPolicies = new PolicyRegistry();
$authPolicies->register('student', new DatabaseResourcePolicy('student'));
$context = new TenantContext(userId: 7, schoolId: 10, branchId: 5, academicYearId: 2026, roles: ['school_admin'], permissions: ['student.view', 'student.create', 'student.update', 'student.delete', 'student.restore']);

$dryDb = new DryRunDatabaseConnection();
$audit = new TamperEvidentAuditLogger(demo_storage_path('audit/db-governance.log'));
$secureDb = new SecureDatabase($dryDb, $authPolicies, $audit, new SecureQueryBuilder($queryGuard), new \Mnb\SecurityCore\Database\SchemaGuard(), $dbPolicies, $queryGuard, new DatabaseResultFilter(), new SchemaMigrationGuard(new SchemaChangePolicy()));

$secureDb->create($context, $studentPolicy, [
    'admission_no' => 'A001',
    'first_name' => 'Ravi',
    'email' => 'ravi@example.com',
    'role_id' => 1,
    'school_id' => 999,
]);
demo_step('Create blocks mass assignment and enforces tenant scope', $dryDb->lastQuery());

$secureDb->search($context, $studentPolicy, 'Ra', [
    'status' => ['eq' => 'active'],
    'class_id' => ['in' => [1, 2, 3]],
    'created_at' => ['between' => ['2026-01-01', '2026-06-30']],
], 'created_at', 'DESC', 25, 0);
demo_step('Advanced safe search filters', $dryDb->lastQuery());

$masked = (new DatabaseResultFilter())->filterRow($context, $studentPolicy, [
    'id' => 1,
    'email' => 'ravi@example.com',
    'phone' => '9876543210',
    'password_hash' => 'never-return-this',
]);
demo_step('Sensitive result fields filtered', $masked);

$blockedLeadingWildcard = false;
try {
    $queryGuard->assertSearch('%bad', [], 25, 0);
} catch (InvalidArgumentException $e) {
    $blockedLeadingWildcard = true;
}
demo_step('Leading wildcard search blocked', $blockedLeadingWildcard);

$secureDb->updateById($context, $studentPolicy, 44, ['first_name' => 'Ravi Updated', 'is_admin' => 1]);
demo_step('Update uses allow-list and scoped WHERE', $dryDb->lastQuery());

$secureDb->deleteById($context, $studentPolicy, 44);
demo_step('Soft delete default', $dryDb->lastQuery());

$secureDb->restoreById($context, $studentPolicy, 44);
demo_step('Restore soft-deleted row', $dryDb->lastQuery());

$transactionOk = $secureDb->transaction($context, function (SecureDatabase $db) use ($context, $studentPolicy): bool {
    $db->updateById($context, $studentPolicy, 45, ['status' => 'active']);
    return true;
});
demo_step('Safe transaction commit', $transactionOk);

$schemaContext = new TenantContext(userId: 1, roles: ['super_admin'], permissions: ['schema.alter']);
$schemaPlan = $secureDb->schemaPlanAddColumn($schemaContext, 'students', 'admission_category', 'VARCHAR(100)', true, null, true);
demo_step('Schema change dry-run plan', $schemaPlan->toArray());

$dropPlan = (new SchemaMigrationGuard())->planDestructive($schemaContext, 'drop_table', 'students');
demo_step('Destructive schema change blocked', $dropPlan->toArray());

$rawBlocked = false;
try {
    RawQueryGuard::fromConfig($config)->assertAllowed('DROP TABLE students');
} catch (InvalidArgumentException $e) {
    $rawBlocked = true;
}
demo_step('Raw SQL blocked', $rawBlocked);

$health = (new DatabaseHealthChecker($config))->check(false);
demo_step('Database health policy check', $health);

$privileges = (new DatabasePrivilegeInspector(['GRANT SELECT, INSERT, UPDATE, DELETE, DROP, ALTER ON app.* TO runtime_user']))->inspect();
demo_step('Database privilege inspector warning', $privileges);

demo_result(
    $dbPolicies->has('students') && $blockedLeadingWildcard && $schemaPlan->allowed && !$dropPlan->allowed && $rawBlocked && !$privileges['passed'] && $audit->verify(),
    'Secure database governance, query lifecycle, field protection, transaction audit, schema planning, and privilege checks are working.'
);
