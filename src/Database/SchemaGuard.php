<?php
namespace Mnb\SecurityCore\Database;

use InvalidArgumentException;
use Mnb\SecurityCore\Authz\TenantContext;

class SchemaGuard
{
    private const ALLOWED_TYPES = [
        'VARCHAR(50)', 'VARCHAR(100)', 'VARCHAR(150)', 'VARCHAR(255)',
        'TEXT', 'INT', 'BIGINT', 'DECIMAL(10,2)', 'DATE', 'DATETIME', 'TINYINT(1)'
    ];

    public function assertSchemaChangeAllowed(TenantContext $context, string $operation = 'schema.alter'): void
    {
        if (!in_array($operation, $context->permissions, true) && !in_array('super_admin', $context->roles, true)) {
            throw new InvalidArgumentException('Schema change blocked: missing schema permission.');
        }
    }

    public function addColumn(string $table, string $column, string $type, bool $nullable = true, mixed $default = null): QueryPlan
    {
        $table = SqlIdentifier::assert($table, 'schema table');
        $column = SqlIdentifier::assert($column, 'schema column');
        $type = strtoupper(trim($type));
        if (!in_array($type, self::ALLOWED_TYPES, true)) {
            throw new InvalidArgumentException("Column type not allowed: {$type}");
        }

        $sql = 'ALTER TABLE ' . $table . ' ADD COLUMN ' . $column . ' ' . $type . ($nullable ? ' NULL' : ' NOT NULL');
        $bindings = [];
        if ($default !== null) {
            $sql .= ' DEFAULT ?';
            $bindings[] = $default;
        }
        return new QueryPlan('alter_add_column', $table, $sql, $bindings, ['column' => $column, 'type' => $type]);
    }

    public function addIndex(string $table, string $indexName, array $columns): QueryPlan
    {
        $table = SqlIdentifier::assert($table, 'schema table');
        $indexName = SqlIdentifier::assert($indexName, 'index name');
        $columns = SqlIdentifier::assertMany($columns, 'index column');
        if (!$columns) {
            throw new InvalidArgumentException('Index requires at least one column.');
        }
        $sql = 'CREATE INDEX ' . $indexName . ' ON ' . $table . ' (' . implode(', ', $columns) . ')';
        return new QueryPlan('alter_add_index', $table, $sql, [], ['columns' => $columns]);
    }
}
