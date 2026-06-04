<?php
require __DIR__ . '/../autoload.php';

use Mnb\SecurityCore\Authz\Policies\DatabaseResourcePolicy;
use Mnb\SecurityCore\Authz\PolicyRegistry;
use Mnb\SecurityCore\Authz\TenantContext;
use Mnb\SecurityCore\Database\DatabaseConfig;
use Mnb\SecurityCore\Database\PdoConnectionFactory;
use Mnb\SecurityCore\Database\SecureDatabase;
use Mnb\SecurityCore\Database\TableSecurityPolicy;
use Mnb\SecurityCore\Logging\TamperEvidentAuditLogger;

$config = DatabaseConfig::fromArray([
    'driver' => 'mysql',
    'host' => $_ENV['DB_HOST'] ?? '127.0.0.1',
    'database' => $_ENV['DB_DATABASE'] ?? 'boss_school',
    'username' => $_ENV['DB_USERNAME'] ?? 'root',
    'password' => $_ENV['DB_PASSWORD'] ?? '',
]);

$db = (new PdoConnectionFactory())->create($config);
$policies = new PolicyRegistry();
$policies->register('student', new DatabaseResourcePolicy('student'));
$audit = new TamperEvidentAuditLogger(__DIR__ . '/../storage/audit/db.log');
$secureDb = new SecureDatabase($db, $policies, $audit);

$studentTable = new TableSecurityPolicy(
    table: 'students',
    resourceType: 'student',
    selectableColumns: ['id', 'admission_no', 'first_name', 'last_name', 'status'],
    insertableColumns: ['admission_no', 'first_name', 'last_name', 'status'],
    updatableColumns: ['first_name', 'last_name', 'status'],
    searchableColumns: ['admission_no', 'first_name', 'last_name'],
    orderableColumns: ['id', 'first_name']
);

$context = TenantContext::fromSession();
$rows = $secureDb->search($context, $studentTable, $_GET['q'] ?? '', ['status' => 'active'], 'id', 'DESC', 50, 0);
header('Content-Type: application/json');
echo json_encode(['status' => true, 'data' => $rows]);
