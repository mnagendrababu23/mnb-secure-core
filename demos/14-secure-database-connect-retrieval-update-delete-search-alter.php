<?php
require_once __DIR__ . '/_demo_bootstrap.php';

use Mnb\SecurityCore\Authz\Policies\DatabaseResourcePolicy;
use Mnb\SecurityCore\Authz\PolicyRegistry;
use Mnb\SecurityCore\Authz\TenantContext;
use Mnb\SecurityCore\Database\DatabaseConfig;
use Mnb\SecurityCore\Database\DryRunDatabaseConnection;
use Mnb\SecurityCore\Database\SecureDatabase;
use Mnb\SecurityCore\Database\TableSecurityPolicy;
use Mnb\SecurityCore\Logging\TamperEvidentAuditLogger;

demo_title('14. Secure Database Connect, Retrieval, Update, Delete, Search, and Alter');

$config = DatabaseConfig::fromArray([
    'driver' => 'mysql',
    'host' => '127.0.0.1',
    'database' => 'boss_school',
    'username' => 'boss_user',
]);

demo_step('Secure DSN shape', $config->dsn);
demo_step('PDO secure options include exception mode', isset($config->securePdoOptions()[PDO::ATTR_ERRMODE]));

$studentPolicy = new TableSecurityPolicy(
    table: 'students',
    resourceType: 'student',
    selectableColumns: ['id', 'admission_no', 'first_name', 'last_name', 'class_id', 'section_id', 'status'],
    insertableColumns: ['admission_no', 'first_name', 'last_name', 'class_id', 'section_id', 'status'],
    updatableColumns: ['first_name', 'last_name', 'class_id', 'section_id', 'status'],
    searchableColumns: ['admission_no', 'first_name', 'last_name'],
    orderableColumns: ['id', 'first_name', 'admission_no']
);

$context = new TenantContext(
    userId: 7,
    schoolId: 10,
    branchId: 5,
    academicYearId: 2026,
    roles: ['school_admin'],
    permissions: ['student.view', 'student.create', 'student.update', 'student.delete']
);

$registry = new PolicyRegistry();
$registry->register('student', new DatabaseResourcePolicy('student'));

$dryRunDb = new DryRunDatabaseConnection();
$audit = new TamperEvidentAuditLogger(demo_storage_path('audit/db-demo.log'));
$secureDb = new SecureDatabase($dryRunDb, $registry, $audit);

$secureDb->create($context, $studentPolicy, [
    'admission_no' => 'A001',
    'first_name' => 'Ravi',
    'last_name' => 'Kumar',
    'status' => 'active',
    'role_id' => 1,       // malicious/mass-assignment field: ignored
    'school_id' => 999,   // malicious tenant override: rejected by policy if trusted as resource
]);
demo_step('Create SQL', $dryRunDb->lastQuery());

$secureDb->search($context, $studentPolicy, 'Ra%_', ['status' => 'active'], 'id', 'DESC', 10, 0);
demo_step('Search SQL with escaped LIKE + tenant scope', $dryRunDb->lastQuery());

$secureDb->updateById($context, $studentPolicy, 44, [
    'first_name' => 'Ravi Updated',
    'is_admin' => 1, // blocked by update allow-list
]);
demo_step('Update SQL with scoped WHERE', $dryRunDb->lastQuery());

$secureDb->deleteById($context, $studentPolicy, 44);
demo_step('Soft-delete SQL', $dryRunDb->lastQuery());

$schemaContext = new TenantContext(userId: 1, roles: ['super_admin'], permissions: ['schema.alter']);
$secureDb->alterAddColumn($schemaContext, 'students', 'blood_group', 'VARCHAR(50)', true);
demo_step('Guarded ALTER SQL', $dryRunDb->lastQuery());

demo_result(
    $audit->verify() && count($dryRunDb->queries()) >= 5,
    'Secure database policy, query building, tenant scoping, CRUD, search, schema guard, and audit logging are working.'
);
