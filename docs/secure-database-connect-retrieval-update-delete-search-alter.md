# Secure Database Connect, Retrieval, Update, Delete, Search, and Alter

**Package:** `mnb/mnb-secure-core`  
**Release line:** `MNB Secure Core v1.0.1`  
**Document type:** Detailed feature documentation and code usage  
**Feature area:** Secure database connection, policy-based CRUD, tenant scoping, safe search filters, soft delete/restore, schema alteration plans, raw SQL blocking, field protection, audit logging, query limits, database health and production readiness

---

## 1. Overview

The **Secure Database Connect, Retrieval, Update, Delete, Search, and Alter** layer protects one of the most important trust boundaries in an application: the database.

It answers questions like:

```text
Is the database connection configured safely?
Are prepared statements enforced?
Can this user read this table or row?
Are only approved columns selectable, insertable, or updatable?
Is tenant scope automatically applied?
Can this search become too expensive?
Are sensitive fields masked or hidden before returning data?
Does delete mean soft delete by default?
Can schema changes run only through safe plans?
Are raw SQL and destructive schema operations blocked?
Are database operations audited without leaking bindings/secrets?
```

This feature does not replace your ORM or framework. Instead, it provides a security-first database governance layer that can be used directly or wrapped around your repositories/services.

The recommended flow is:

```text
Application service / controller
    ↓
TenantContext + authorization permissions
    ↓
TableSecurityPolicy / DatabasePolicyRegistry
    ↓
QueryComplexityGuard + SecureQueryBuilder
    ↓
DatabaseConnectionInterface / PDO prepared statements
    ↓
DatabaseResultFilter / field protection
    ↓
Audit trail with SQL shape, not raw secrets
```

---

## 2. What This Feature Protects Against

The database layer helps reduce risk from:

```text
SQL injection
Mass assignment
Broken access control
IDOR / object-level authorization failure
Tenant data leakage
Unsafe column selection
Sensitive data exposure
Password/API token leakage in result sets
Unsafe hard delete
Unbounded search and expensive query DoS
Unsafe sorting/filtering
Raw SQL abuse
Dangerous schema alteration
Destructive migration mistakes
Missing database audit trail
Overpowered database credentials
```

A secure database layer is not only about prepared statements. It also needs policy-based table access, tenant scoping, safe query construction, field-level result protection, and schema-change governance.

---

## 3. Main Classes

The database layer is mainly built around these classes:

```text
Mnb\SecurityCore\Database\DatabaseConfig
Mnb\SecurityCore\Database\PdoConnectionFactory
Mnb\SecurityCore\Database\PdoDatabaseConnection
Mnb\SecurityCore\Database\DryRunDatabaseConnection
Mnb\SecurityCore\Contracts\DatabaseConnectionInterface

Mnb\SecurityCore\Database\SecureDatabase
Mnb\SecurityCore\Database\SecureQueryBuilder
Mnb\SecurityCore\Database\TableSecurityPolicy
Mnb\SecurityCore\Database\DatabasePolicyRegistry
Mnb\SecurityCore\Database\SqlIdentifier
Mnb\SecurityCore\Database\QueryPlan

Mnb\SecurityCore\Database\DatabaseSearchFilter
Mnb\SecurityCore\Database\DatabaseFilterOperator
Mnb\SecurityCore\Database\QueryCostPolicy
Mnb\SecurityCore\Database\QueryComplexityGuard

Mnb\SecurityCore\Database\DatabaseFieldProtection
Mnb\SecurityCore\Database\DatabaseResultFilter
Mnb\SecurityCore\Database\RawQueryGuard
Mnb\SecurityCore\Database\SafeTransaction

Mnb\SecurityCore\Database\SchemaGuard
Mnb\SecurityCore\Database\SchemaChangePolicy
Mnb\SecurityCore\Database\SchemaChangePlan
Mnb\SecurityCore\Database\SchemaMigrationGuard

Mnb\SecurityCore\Database\DatabaseHealthChecker
Mnb\SecurityCore\Database\DatabasePrivilegeInspector
Mnb\SecurityCore\Database\DatabaseAuditEvents
```

The common access points on `SecurityKernel` are:

```php
$kernel->secureDatabase($connection, $audit = null, $tablePolicies = []);
$kernel->databasePolicyRegistry($policies = []);
$kernel->databaseQueryCostPolicy();
$kernel->databaseQueryGuard();
$kernel->databaseFieldResultFilter();
$kernel->rawQueryGuard();
$kernel->schemaChangePolicy();
$kernel->schemaMigrationGuard();
$kernel->databaseHealthChecker($connection = null);
$kernel->databasePrivilegeInspector($grantsOrPrivileges = []);
$kernel->pdo();
```

---

## 4. Installation

Install the package through Composer:

```bash
composer require mnb/mnb-secure-core
```

Load Composer autoload:

```php
require __DIR__ . '/vendor/autoload.php';
```

---

## 5. Basic Configuration

A practical database config block looks like this:

```php
use Mnb\SecurityCore\Core\SecurityKernel;

$config = [
    'app' => [
        'env' => 'production',
        'debug' => false,
    ],

    'database' => [
        'driver' => getenv('DB_DRIVER') ?: 'mysql',
        'host' => getenv('DB_HOST') ?: '127.0.0.1',
        'port' => getenv('DB_PORT') ?: '3306',
        'database' => getenv('DB_DATABASE') ?: 'app_db',
        'username' => getenv('DB_USERNAME') ?: 'app_user',
        'password' => getenv('DB_PASSWORD') ?: '',
        'charset' => getenv('DB_CHARSET') ?: 'utf8mb4',

        'require_policies' => true,
        'soft_delete_default' => true,
        'deny_raw_sql' => true,
        'audit_queries' => true,
        'audit_bindings' => false,

        'query_limits' => [
            'max_limit' => 500,
            'default_limit' => 50,
            'max_offset' => 10000,
            'max_search_length' => 100,
            'max_filter_count' => 20,
            'block_leading_wildcard' => true,
            'slow_query_ms' => 750,
        ],

        'transactions' => [
            'enabled' => true,
            'max_operations' => 50,
            'audit_begin_commit_rollback' => true,
        ],

        'schema_changes' => [
            'enabled' => true,
            'require_super_admin' => true,
            'require_backup_before_alter' => true,
            'allow_destructive_changes' => false,
            'dry_run_default' => true,
            'allowed_operations' => [
                'add_column',
                'add_index',
            ],
        ],

        'field_protection' => [
            'enabled' => true,
            'mask_sensitive_columns' => true,
            'deny_password_columns' => true,
        ],
    ],
];

$kernel = new SecurityKernel($config);
```

For production, keep database credentials in `.env` or a secret manager. Do not commit credentials to Git.

---

## 6. Secure Database Connection

### 6.1 Create a PDO-backed connection

```php
use Mnb\SecurityCore\Database\DatabaseConfig;
use Mnb\SecurityCore\Database\PdoConnectionFactory;

$dbConfig = DatabaseConfig::fromArray($config['database']);
$connection = (new PdoConnectionFactory())->create($dbConfig);
```

`DatabaseConfig::securePdoOptions()` uses safe PDO defaults:

```text
PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
PDO::ATTR_EMULATE_PREPARES => false
PDO::ATTR_STRINGIFY_FETCHES => false
```

That means queries use real prepared statements where supported, fetch associative rows by default, and fail loudly instead of silently ignoring database errors.

### 6.2 Use the kernel helper

If your config already contains the database block, you can get raw PDO through:

```php
$pdo = $kernel->pdo();
```

For secure CRUD, prefer `SecureDatabase` instead of raw PDO.

---

## 7. DatabaseConnectionInterface

`SecureDatabase` works with `DatabaseConnectionInterface`, so you can plug in PDO, a framework adapter, a dry-run adapter, or a test adapter.

```php
namespace Mnb\SecurityCore\Contracts;

interface DatabaseConnectionInterface
{
    public function fetchAll(string $sql, array $bindings = []): array;
    public function fetchOne(string $sql, array $bindings = []): ?array;
    public function execute(string $sql, array $bindings = []): int;
    public function transaction(callable $callback): mixed;
    public function lastInsertId(): string;
}
```

This keeps database security portable across frameworks.

---

## 8. Table Security Policies

Every protected table should have a `TableSecurityPolicy`.

A table policy defines:

```text
Table name
Resource type
Selectable columns
Insertable columns
Updatable columns
Searchable columns
Orderable columns
Primary key
Tenant columns
Soft-delete behavior
Sensitive/hidden/masked columns
Permission-required columns
```

Example policy:

```php
use Mnb\SecurityCore\Database\TableSecurityPolicy;

$studentPolicy = new TableSecurityPolicy(
    table: 'students',
    resourceType: 'student',
    selectableColumns: [
        'id',
        'school_id',
        'branch_id',
        'academic_year_id',
        'name',
        'email',
        'phone',
        'status',
        'created_at',
    ],
    insertableColumns: [
        'name',
        'email',
        'phone',
        'status',
    ],
    updatableColumns: [
        'name',
        'email',
        'phone',
        'status',
    ],
    searchableColumns: [
        'name',
        'email',
        'phone',
    ],
    orderableColumns: [
        'id',
        'name',
        'created_at',
    ],
    primaryKey: 'id',
    tenantColumns: [
        'school_id' => 'schoolId',
        'branch_id' => 'branchId',
        'academic_year_id' => 'academicYearId',
    ],
    softDeletes: true,
    deletedAtColumn: 'deleted_at',
    sensitiveColumns: ['email', 'phone'],
    hiddenColumns: ['password_hash', 'api_token'],
    maskedColumns: ['email', 'phone'],
    permissionColumns: [
        'internal_notes' => 'student.view_internal_notes',
    ]
);
```

Important rule: **never include dangerous system fields in insertable/updatable columns unless absolutely required**.

Avoid making these user-writable:

```text
id
school_id
branch_id
academic_year_id
role
is_admin
password_hash
api_token
created_by
deleted_at
```

Tenant columns should usually come from `TenantContext`, not from user input.

---

## 9. Register Policies Once

Use `DatabasePolicyRegistry` to register policies once and refer to them by name, table, or resource type.

```php
$registry = $kernel->databasePolicyRegistry([
    'students' => $studentPolicy,
]);

$policy = $registry->get('students');
```

You can also pass policies into `secureDatabase()`:

```php
$secureDb = $kernel->secureDatabase(
    connection: $connection,
    audit: null,
    tablePolicies: [
        'students' => $studentPolicy,
    ]
);
```

Then use policy-name helpers:

```php
$rows = $secureDb->searchPolicy(
    context: $context,
    policyName: 'students',
    term: 'Ravi',
    filters: ['status' => ['eq' => 'active']],
    orderBy: 'created_at',
    direction: 'DESC',
    limit: 25,
    offset: 0
);
```

---

## 10. TenantContext and Authorization

Database operations require a `TenantContext`.

```php
use Mnb\SecurityCore\Authz\TenantContext;

$context = new TenantContext(
    userId: 42,
    roles: ['teacher'],
    permissions: [
        'student.view',
        'student.create',
        'student.update',
        'student.delete',
        'student.restore',
    ],
    schoolId: 10,
    branchId: 2,
    academicYearId: 2026
);
```

`SecureDatabase` checks authorization before executing operations.

Permission names are based on the resource type and operation:

```text
student.view
student.create
student.update
student.delete
student.hard_delete
student.restore
schema.alter
```

A user with `super_admin` role can bypass normal resource permission checks, but use this carefully.

---

## 11. Secure Retrieval

### 11.1 Search records

```php
$students = $secureDb->search(
    context: $context,
    policy: $studentPolicy,
    term: 'ravi',
    filters: [
        'status' => ['eq' => 'active'],
    ],
    orderBy: 'created_at',
    direction: 'DESC',
    limit: 25,
    offset: 0
);
```

The query builder automatically applies:

```text
Selectable column allow-list
Searchable column allow-list
Filter column allow-list
Order-by allow-list
Tenant scope conditions
Limit/offset bounds
Prepared statement bindings
LIKE escaping
Field-level result filtering
Audit event
```

### 11.2 Find by ID

```php
$student = $secureDb->findById(
    context: $context,
    policy: $studentPolicy,
    id: 1001
);
```

This does not simply run `WHERE id = ?`. It also adds tenant scope from the context.

Conceptually:

```sql
SELECT id, school_id, branch_id, name, email
FROM students
WHERE id = ?
  AND school_id = ?
  AND branch_id = ?
  AND academic_year_id = ?
LIMIT 1
```

This helps prevent IDOR and tenant data leakage.

---

## 12. Secure Create

```php
$id = $secureDb->create(
    context: $context,
    policy: $studentPolicy,
    data: [
        'name' => 'Ravi Kumar',
        'email' => 'ravi@example.com',
        'phone' => '+91 90000 00000',
        'status' => 'active',

        // Ignored/blocked because not insertable:
        'is_admin' => true,
        'school_id' => 999,
    ]
);
```

The builder only keeps allowed insert fields and merges tenant scope from `TenantContext`.

This protects against mass assignment attacks such as:

```text
is_admin = true
role = super_admin
school_id = another school
password_hash = attacker-controlled value
```

---

## 13. Secure Update

```php
$affected = $secureDb->updateById(
    context: $context,
    policy: $studentPolicy,
    id: 1001,
    data: [
        'phone' => '+91 98888 00000',
        'status' => 'inactive',

        // Not allowed unless explicitly listed in updatableColumns:
        'role' => 'admin',
    ]
);
```

Update protection includes:

```text
Update column allow-list
Tenant-scoped WHERE clause
Prepared statement bindings
Authorization check
Audit event
```

If no allowed columns remain after filtering, the update is rejected.

---

## 14. Secure Delete and Restore

### 14.1 Soft delete by default

```php
$affected = $secureDb->deleteById(
    context: $context,
    policy: $studentPolicy,
    id: 1001
);
```

When `softDeletes` is enabled, delete becomes:

```sql
UPDATE students SET deleted_at = ? WHERE id = ? AND school_id = ?
```

This supports recovery and safer admin workflows.

### 14.2 Restore

```php
$affected = $secureDb->restoreById(
    context: $context,
    policy: $studentPolicy,
    id: 1001
);
```

Restore requires the relevant permission, for example:

```text
student.restore
```

### 14.3 Hard delete

```php
$affected = $secureDb->deleteById(
    context: $context,
    policy: $studentPolicy,
    id: 1001,
    hardDelete: true
);
```

Hard delete should require stronger permission:

```text
student.hard_delete
```

Recommended production rule: use hard delete only for retention-policy cleanup, not normal admin actions.

---

## 15. Secure Search Filters

The database engine supports safe filter operators through `DatabaseFilterOperator`.

Allowed operators:

```text
eq
neq
in
not_in
like
starts_with
ends_with
between
gte
lte
gt
lt
is_null
is_not_null
```

Example:

```php
$filters = [
    'status' => ['eq' => 'active'],
    'class_id' => ['in' => [1, 2, 3]],
    'created_at' => ['between' => ['2026-01-01', '2026-06-30']],
    'name' => ['starts_with' => 'Ra'],
];

$rows = $secureDb->search(
    $context,
    $studentPolicy,
    term: '',
    filters: $filters,
    orderBy: 'created_at',
    direction: 'DESC',
    limit: 50,
    offset: 0
);
```

The builder validates the column name, validates the operator, escapes LIKE patterns, and binds every value.

Do not pass raw SQL snippets as filters.

Bad:

```php
$filters = [
    'status = active OR 1=1' => 'anything',
];
```

Good:

```php
$filters = [
    'status' => ['eq' => 'active'],
];
```

---

## 16. Query Complexity Limits

`QueryComplexityGuard` protects search endpoints from abusive or accidentally expensive queries.

```php
$guard = $kernel->databaseQueryGuard();

$guard->assertSearch(
    searchTerm: 'student',
    filters: ['status' => ['eq' => 'active']],
    limit: 50,
    offset: 0
);
```

Limits are configured through `database.query_limits`:

```php
'query_limits' => [
    'max_limit' => 500,
    'default_limit' => 50,
    'max_offset' => 10000,
    'max_search_length' => 100,
    'max_filter_count' => 20,
    'block_leading_wildcard' => true,
    'slow_query_ms' => 750,
],
```

This helps protect against:

```text
Large result pulls
Extreme offsets
Huge filter arrays
Long search strings
Expensive wildcard search
Search-based denial of service
```

---

## 17. Field-Level Result Protection

`DatabaseResultFilter` and `DatabaseFieldProtection` protect sensitive fields before rows leave the database layer.

Example policy fields:

```php
$studentPolicy = new TableSecurityPolicy(
    table: 'students',
    resourceType: 'student',
    selectableColumns: ['id', 'name', 'email', 'phone', 'password_hash', 'internal_notes'],
    insertableColumns: ['name', 'email', 'phone'],
    updatableColumns: ['name', 'email', 'phone'],
    sensitiveColumns: ['email', 'phone'],
    hiddenColumns: ['password_hash'],
    maskedColumns: ['email', 'phone'],
    permissionColumns: [
        'internal_notes' => 'student.view_internal_notes',
    ]
);
```

A normal user may get:

```php
[
    'id' => 1001,
    'name' => 'Ravi Kumar',
    'email' => 'r***@example.com',
    'phone' => '+91******0000',
]
```

And not get:

```text
password_hash
api_token
internal_notes without permission
```

This gives a second protection layer in case a sensitive column is accidentally included in `selectableColumns`.

---

## 18. Raw SQL Guard

Raw SQL should be avoided in application code. Use `SecureDatabase` and `SecureQueryBuilder` wherever possible.

For extra safety, use `RawQueryGuard` before any trusted escape hatch:

```php
$rawGuard = $kernel->rawQueryGuard();

$rawGuard->assertAllowed(
    sql: 'SELECT id, name FROM students WHERE status = ?',
    trusted: false
);
```

If `database.deny_raw_sql` is enabled, this rejects untrusted raw SQL.

Dangerous operations are also blocked:

```text
DROP
TRUNCATE
RENAME
GRANT
REVOKE
CREATE USER
ALTER USER
```

If a migration system really needs raw SQL, keep it separate from runtime application credentials and mark it trusted only inside reviewed migration tooling.

---

## 19. Safe Transactions

`SecureDatabase` includes a transaction helper:

```php
$result = $secureDb->transaction($context, function ($db) use ($context, $studentPolicy) {
    $id = $db->create($context, $studentPolicy, [
        'name' => 'New Student',
        'email' => 'student@example.com',
        'status' => 'active',
    ]);

    $db->updateById($context, $studentPolicy, $id, [
        'status' => 'verified',
    ]);

    return $id;
});
```

Transaction audit events include:

```text
db.transaction.begin
db.transaction.commit
db.transaction.rollback
```

Use transactions for multi-step operations that must succeed or fail together.

---

## 20. Secure Schema Alteration

Schema changes are dangerous. Runtime apps should not freely run `ALTER TABLE`, `DROP TABLE`, or `TRUNCATE`.

MNB Secure Core supports safe schema planning for controlled operations such as:

```text
add_column
add_index
```

### 20.1 Create an add-column plan

```php
$plan = $secureDb->schemaPlanAddColumn(
    context: $context,
    table: 'students',
    column: 'admission_number',
    type: 'VARCHAR(100)',
    nullable: true,
    default: null,
    dryRun: true
);

print_r($plan->toArray());
```

A dry-run plan can show:

```text
operation: add_column
table: students
column: admission_number
type: VARCHAR(100)
dry_run: true
destructive: false
allowed: true
requires_backup: true
```

### 20.2 Create an add-index plan

```php
$plan = $secureDb->schemaPlanAddIndex(
    context: $context,
    table: 'students',
    indexName: 'idx_students_status',
    columns: ['status'],
    dryRun: true
);
```

### 20.3 Legacy direct alter helpers

The lower-level helpers exist:

```php
$secureDb->alterAddColumn($context, 'students', 'admission_number', 'VARCHAR(100)');
$secureDb->alterAddIndex($context, 'students', 'idx_students_status', ['status']);
```

For production, prefer schema plans and reviewed migrations.

---

## 21. Allowed Schema Types

`SchemaGuard` allows controlled column types such as:

```text
VARCHAR(50)
VARCHAR(100)
VARCHAR(150)
VARCHAR(255)
TEXT
INT
BIGINT
DECIMAL(10,2)
DATE
DATETIME
TINYINT(1)
```

Unsafe or unknown types should be rejected.

Avoid runtime schema operations like:

```text
DROP TABLE
DROP COLUMN
TRUNCATE
RENAME TABLE
ALTER COLUMN destructive changes
```

---

## 22. Database Health Checks

Use `DatabaseHealthChecker` to check configuration readiness.

```php
$health = $kernel->databaseHealthChecker($connection)->check(connect: true);

if (!$health['passed']) {
    print_r($health['issues']);
}
```

The checker validates:

```text
Supported driver
Safe charset
PDO exception mode
Emulated prepares disabled
Stringify fetches disabled
Optional connection check
Safe DSN shape
```

CLI examples:

```bash
php bin/mnb-secure db:health
php bin/mnb-secure db:check-connection
```

---

## 23. Database Privilege Inspection

Your runtime DB user should not be overpowered.

Recommended split:

```text
runtime_user   → SELECT, INSERT, UPDATE, DELETE
migration_user → CREATE, ALTER, INDEX
readonly_user  → SELECT only
```

Use the inspector with database grants or privilege strings:

```php
$report = $kernel->databasePrivilegeInspector([
    'GRANT SELECT, INSERT, UPDATE, DELETE ON app_db.* TO app_user',
])->inspect();

print_r($report);
```

Dangerous privileges include:

```text
DROP
ALTER
CREATE USER
GRANT
SUPER
FILE
SHUTDOWN
PROCESS
RELOAD
```

CLI:

```bash
php bin/mnb-secure db:privileges
```

---

## 24. CLI Commands

Database CLI commands include:

```bash
php bin/mnb-secure db:health
php bin/mnb-secure db:check-connection
php bin/mnb-secure db:policy
php bin/mnb-secure db:query-limits
php bin/mnb-secure db:schema-plan add_column students admission_number "VARCHAR(100)"
php bin/mnb-secure db:privileges
```

Related vulnerability checks:

```bash
php bin/mnb-secure vulnerabilities:check sql_injection
php bin/mnb-secure vulnerabilities:check mass_assignment
php bin/mnb-secure vulnerabilities:check idor
php bin/mnb-secure vulnerabilities:check dangerous_schema_alteration
```

---

## 25. Controller / Service Example

Example service method for a secure search endpoint:

```php
use Mnb\SecurityCore\Authz\TenantContext;
use Mnb\SecurityCore\Database\SecureDatabase;
use Mnb\SecurityCore\Database\TableSecurityPolicy;

final class StudentSearchService
{
    public function __construct(
        private SecureDatabase $db,
        private TableSecurityPolicy $studentPolicy
    ) {}

    public function search(TenantContext $context, array $input): array
    {
        $term = trim((string)($input['q'] ?? ''));
        $limit = min((int)($input['limit'] ?? 25), 100);

        return $this->db->search(
            context: $context,
            policy: $this->studentPolicy,
            term: $term,
            filters: [
                'status' => ['eq' => $input['status'] ?? 'active'],
            ],
            orderBy: 'created_at',
            direction: 'DESC',
            limit: $limit,
            offset: max(0, (int)($input['offset'] ?? 0))
        );
    }
}
```

The controller should not build raw SQL. It should pass user inputs into safe filters and let the database layer build the query.

---

## 26. Repository Pattern Example

You can wrap `SecureDatabase` in a repository:

```php
final class StudentRepository
{
    public function __construct(
        private SecureDatabase $db,
        private TableSecurityPolicy $policy
    ) {}

    public function find(TenantContext $context, int $id): ?array
    {
        return $this->db->findById($context, $this->policy, $id);
    }

    public function create(TenantContext $context, array $data): string
    {
        return $this->db->create($context, $this->policy, $data);
    }

    public function update(TenantContext $context, int $id, array $data): int
    {
        return $this->db->updateById($context, $this->policy, $id, $data);
    }

    public function delete(TenantContext $context, int $id): int
    {
        return $this->db->deleteById($context, $this->policy, $id);
    }
}
```

This keeps application code clean while preserving security enforcement.

---

## 27. Queue / Background Job Integration

Expensive database work should not always run inside HTTP requests.

Good candidates for background jobs:

```text
Large exports
Audit exports
Backup jobs
Report generation
Bulk imports
Large cleanup jobs
Schema-change review tasks
```

Use the queue engine for async processing:

```php
$job = $kernel->jobDispatcher()->dispatch(
    name: 'database_export',
    payload: [
        'export_id' => $exportId,
        'requested_by' => $context->userId,
    ],
    queue: 'exports',
    idempotencyKey: 'database_export:' . $exportId
);
```

The database engine provides query safety; the queue engine controls long-running execution.

---

## 28. Memory and Throughput Integration

Database operations should respect memory and capacity limits.

Recommended rules:

```text
Use query limits for every search endpoint
Avoid fetchAll() for huge exports in application code
Use chunked processing for large result sets
Queue expensive exports
Use throughput profiles for database_export
Use memory profile database_export for large export jobs
```

For large exports, use safe pagination/chunking:

```php
$offset = 0;
$limit = 500;

while (true) {
    $rows = $secureDb->search(
        $context,
        $studentPolicy,
        term: '',
        filters: ['status' => ['eq' => 'active']],
        orderBy: 'id',
        direction: 'ASC',
        limit: $limit,
        offset: $offset
    );

    if ($rows === []) {
        break;
    }

    // Write chunk to stream/exporter here.
    $offset += $limit;
}
```

---

## 29. Audit Behavior

`SecureDatabase` records audit events such as:

```text
db.search
db.find
db.create
db.update
db.delete
db.hard_delete
db.restore
db.transaction.begin
db.transaction.commit
db.transaction.rollback
db.schema.plan_created
db.schema.add_column
db.schema.add_index
```

Audit metadata includes SQL shape and binding count, not raw secret values.

Example audit metadata:

```php
[
    'operation' => 'select',
    'sql_shape' => 'SELECT id, name FROM students WHERE status = ? LIMIT 50 OFFSET 0',
    'binding_count' => 1,
]
```

Do not enable raw binding logs in production unless you have a strict redaction and privacy policy.

---

## 30. Safe Error Handling

Database exceptions should pass through the safe error layer.

Frontend users should not see:

```text
SQLSTATE[HY000]
PDOException stack traces
Database usernames
Database hostnames
Raw SQL queries
File paths
```

They should receive a safe response with a request ID:

```json
{
  "status": false,
  "message": "Something went wrong. Please try again later.",
  "error": {
    "code": "INTERNAL_ERROR",
    "request_id": "req_..."
  }
}
```

Developers can use hidden logs and audit records to diagnose the issue.

---

## 31. Testing Examples

### 31.1 Policy blocks unknown columns

```php
try {
    $secureDb->search(
        $context,
        $studentPolicy,
        term: '',
        filters: ['password_hash' => ['eq' => 'x']],
        limit: 10,
        offset: 0
    );
    assert(false, 'Expected filter to be blocked.');
} catch (InvalidArgumentException $e) {
    assert(str_contains($e->getMessage(), 'Filter column not allowed'));
}
```

### 31.2 Tenant scope is applied

```php
$plan = (new SecureQueryBuilder())->findById(
    policy: $studentPolicy,
    id: 1001,
    tenantScopes: ['school_id' => 10],
    columns: ['id', 'name']
);

assert(str_contains($plan->sql, 'school_id = ?'));
assert(in_array(10, $plan->bindings, true));
```

### 31.3 Mass assignment is blocked

```php
$plan = (new SecureQueryBuilder())->insert(
    policy: $studentPolicy,
    data: [
        'name' => 'Ravi',
        'is_admin' => true,
    ],
    tenantScopes: ['school_id' => 10]
);

assert(!str_contains($plan->sql, 'is_admin'));
```

### 31.4 Query complexity blocks large limits

```php
$guard = $kernel->databaseQueryGuard();

try {
    $guard->assertSearch('abc', [], 999999, 0);
    assert(false, 'Expected large query limit to be blocked.');
} catch (InvalidArgumentException $e) {
    assert(str_contains($e->getMessage(), 'Query limit'));
}
```

### 31.5 Raw SQL is blocked

```php
try {
    $kernel->rawQueryGuard()->assertAllowed('DROP TABLE students');
    assert(false, 'Expected raw SQL to be blocked.');
} catch (InvalidArgumentException $e) {
    assert(true);
}
```

---

## 32. Demo File

The database feature is demonstrated in:

```text
demos/32-secure-database-governance-query-lifecycle-engine.php
```

Depending on the package state, earlier database basics may also be shown in:

```text
demos/14-secure-database-connect-retrieval-update-delete-search-alter.php
```

Run all demos:

```bash
php demos/run-all-demos.php
```

---

## 33. Production Checklist

Before enabling database operations in production, verify:

```text
[ ] Database credentials are loaded from environment/secret manager.
[ ] Runtime DB user does not have DROP/GRANT/SUPER/FILE privileges.
[ ] Migration credentials are separated from runtime credentials.
[ ] PDO emulated prepares are disabled.
[ ] PDO errors use exceptions.
[ ] MySQL/MariaDB uses utf8mb4.
[ ] Every protected table has a TableSecurityPolicy.
[ ] Selectable/insertable/updatable columns are minimal.
[ ] Tenant columns are mapped from TenantContext.
[ ] User input cannot override tenant scope.
[ ] Searchable/orderable columns are allow-listed.
[ ] Query limits are enabled.
[ ] Soft delete is default where recovery is required.
[ ] Hard delete requires stronger permission.
[ ] Sensitive fields are hidden or masked.
[ ] Password/API token columns are never returned.
[ ] Raw SQL is disabled or strictly guarded.
[ ] Schema changes are dry-run planned and reviewed.
[ ] Backup-before-alter is required for production schema changes.
[ ] Database audit events are enabled.
[ ] Audit logs do not store raw bindings/secrets.
[ ] Safe error handling hides SQL errors from users.
[ ] Expensive exports/reports are queued.
[ ] Database health checks pass.
```

---

## 34. Common Mistakes

### Mistake: using raw PDO directly in controllers

Bad:

```php
$pdo->query("SELECT * FROM students WHERE id = " . $_GET['id']);
```

Good:

```php
$student = $secureDb->findById($context, $studentPolicy, (int)$_GET['id']);
```

### Mistake: allowing all columns

Bad:

```php
selectableColumns: ['*']
```

Good:

```php
selectableColumns: ['id', 'name', 'status', 'created_at']
```

### Mistake: trusting tenant ID from request body

Bad:

```php
$data['school_id'] = $_POST['school_id'];
```

Good:

```php
// school_id comes from TenantContext and policy tenantColumns
```

### Mistake: hard deleting records by default

Bad:

```php
$secureDb->deleteById($context, $policy, $id, hardDelete: true);
```

Good:

```php
$secureDb->deleteById($context, $policy, $id);
```

### Mistake: putting secrets in audit logs

Bad:

```php
'audit_bindings' => true
```

Good:

```php
'audit_bindings' => false
```

---

## 35. Suggested Application Architecture

A clean application structure looks like this:

```text
Controller
    ↓
Request validation
    ↓
TenantContext creation
    ↓
Authorization check / SecureDatabase operation
    ↓
DatabaseResultFilter
    ↓
Safe API response
```

For heavy operations:

```text
Controller
    ↓
Authorize request
    ↓
Queue database_export job
    ↓
Return 202 Accepted
    ↓
Worker runs SecureDatabase search/chunking
    ↓
Protected download generated
```

For schema changes:

```text
Admin request
    ↓
Super-admin authorization
    ↓
Schema dry-run plan
    ↓
Backup requirement check
    ↓
Manual review / migration process
    ↓
Audit trail
```

---

## 36. Quick Reference

```php
// Connection
$connection = (new PdoConnectionFactory())->create(DatabaseConfig::fromArray($config['database']));

// Secure DB
$secureDb = $kernel->secureDatabase($connection, tablePolicies: ['students' => $studentPolicy]);

// Search
$rows = $secureDb->search($context, $studentPolicy, 'ravi', ['status' => ['eq' => 'active']], 'created_at', 'DESC', 25, 0);

// Find
$row = $secureDb->findById($context, $studentPolicy, 1001);

// Create
$id = $secureDb->create($context, $studentPolicy, ['name' => 'Ravi', 'status' => 'active']);

// Update
$affected = $secureDb->updateById($context, $studentPolicy, 1001, ['status' => 'inactive']);

// Soft delete
$affected = $secureDb->deleteById($context, $studentPolicy, 1001);

// Restore
$affected = $secureDb->restoreById($context, $studentPolicy, 1001);

// Schema plan
$plan = $secureDb->schemaPlanAddColumn($context, 'students', 'admission_number', 'VARCHAR(100)', true, null, true);

// Health
$health = $kernel->databaseHealthChecker($connection)->check(connect: true);
```

---

## 37. Summary

The database layer in `mnb/mnb-secure-core` provides a security-first way to connect to databases and perform CRUD/search/schema operations.

It protects database access by combining:

```text
Secure PDO configuration
Prepared statement bindings
SQL identifier validation
Table security policies
Tenant scoping
Authorization checks
Column allow-lists
Query complexity limits
Field-level result protection
Soft delete and restore
Raw SQL blocking
Safe transaction workflow
Schema dry-run planning
Health and privilege checks
Audit logging
```

Use `SecureDatabase` for runtime application database operations, keep migrations separate from normal runtime credentials, and always define explicit table policies for sensitive data.
