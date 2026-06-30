<?php
namespace Mnb\SecurityCore\Database;

use InvalidArgumentException;

class SecureQueryBuilder
{
    public function __construct(private ?QueryComplexityGuard $queryGuard = null) {}

    public function select(
        TableSecurityPolicy $policy,
        array $columns,
        array $filters = [],
        array $tenantScopes = [],
        ?string $searchTerm = null,
        array $searchColumns = [],
        ?string $orderBy = null,
        string $direction = 'ASC',
        int $limit = 50,
        int $offset = 0
    ): QueryPlan {
        $this->guard()->assertSearch($searchTerm, $filters, $limit, $offset);

        $table = SqlIdentifier::assert($policy->table, 'table');
        $allowedSelect = $policy->selectableColumns;
        $columns = $columns ?: $allowedSelect;
        $columns = $this->allowedColumns($columns, $allowedSelect, 'select');

        [$whereSql, $bindings] = $this->where($filters, array_merge($allowedSelect, array_keys($tenantScopes), [$policy->primaryKey]));
        [$tenantSql, $tenantBindings] = $this->where($tenantScopes, array_merge(array_keys($tenantScopes), [$policy->primaryKey]));
        $whereSql = array_merge($whereSql, $tenantSql);
        $bindings = array_merge($bindings, $tenantBindings);

        if ($searchTerm !== null && trim($searchTerm) !== '') {
            $searchColumns = $this->allowedColumns($searchColumns ?: $policy->searchableColumns, $policy->searchableColumns, 'search');
            if (!$searchColumns) {
                throw new InvalidArgumentException('Search requested but no searchable columns are allowed.');
            }
            $likes = [];
            foreach ($searchColumns as $col) {
                $likes[] = SqlIdentifier::assert($col, 'search column') . " LIKE ? ESCAPE '\\\\'";
                $bindings[] = '%' . $this->escapeLike($searchTerm) . '%';
            }
            $whereSql[] = '(' . implode(' OR ', $likes) . ')';
        }

        $sql = 'SELECT ' . implode(', ', $columns) . ' FROM ' . $table;
        if ($whereSql) {
            $sql .= ' WHERE ' . implode(' AND ', $whereSql);
        }

        if ($orderBy !== null) {
            if (!in_array($orderBy, $policy->orderableColumns, true)) {
                throw new InvalidArgumentException("Order by column not allowed: {$orderBy}");
            }
            $dir = strtoupper($direction) === 'DESC' ? 'DESC' : 'ASC';
            $sql .= ' ORDER BY ' . SqlIdentifier::assert($orderBy, 'order column') . ' ' . $dir;
        }

        $maxLimit = $this->guard()->policy()->maxLimit;
        $limit = max(1, min($limit, $maxLimit));
        $offset = max(0, min($offset, $this->guard()->policy()->maxOffset));
        $sql .= ' LIMIT ' . $limit . ' OFFSET ' . $offset;

        return new QueryPlan('select', $table, $sql, $bindings, ['limit' => $limit, 'offset' => $offset]);
    }

    public function findById(TableSecurityPolicy $policy, int|string $id, array $tenantScopes = [], array $columns = []): QueryPlan
    {
        return $this->select($policy, $columns, [$policy->primaryKey => $id], $tenantScopes, null, [], null, 'ASC', 1, 0);
    }

    public function insert(TableSecurityPolicy $policy, array $data, array $tenantScopes = []): QueryPlan
    {
        $table = SqlIdentifier::assert($policy->table, 'table');
        $data = array_merge($this->onlyAllowed($data, $policy->insertableColumns, 'insert'), $tenantScopes);
        if (!$data) {
            throw new InvalidArgumentException('Insert data is empty after allow-list filtering.');
        }
        $columns = SqlIdentifier::assertMany(array_keys($data), 'insert column');
        $placeholders = array_fill(0, count($columns), '?');
        $sql = 'INSERT INTO ' . $table . ' (' . implode(', ', $columns) . ') VALUES (' . implode(', ', $placeholders) . ')';
        return new QueryPlan('insert', $table, $sql, array_values($data));
    }

    public function updateById(TableSecurityPolicy $policy, int|string $id, array $data, array $tenantScopes = []): QueryPlan
    {
        $table = SqlIdentifier::assert($policy->table, 'table');
        $data = $this->onlyAllowed($data, $policy->updatableColumns, 'update');
        if (!$data) {
            throw new InvalidArgumentException('Update data is empty after allow-list filtering.');
        }
        $sets = [];
        $bindings = [];
        foreach ($data as $col => $value) {
            $sets[] = SqlIdentifier::assert((string)$col, 'update column') . ' = ?';
            $bindings[] = $value;
        }
        [$whereSql, $whereBindings] = $this->where([$policy->primaryKey => $id] + $tenantScopes, [$policy->primaryKey, ...array_keys($tenantScopes)]);
        $sql = 'UPDATE ' . $table . ' SET ' . implode(', ', $sets) . ' WHERE ' . implode(' AND ', $whereSql);
        return new QueryPlan('update', $table, $sql, array_merge($bindings, $whereBindings));
    }

    public function deleteById(TableSecurityPolicy $policy, int|string $id, array $tenantScopes = [], bool $hardDelete = false): QueryPlan
    {
        $table = SqlIdentifier::assert($policy->table, 'table');
        [$whereSql, $bindings] = $this->where([$policy->primaryKey => $id] + $tenantScopes, [$policy->primaryKey, ...array_keys($tenantScopes)]);
        if ($hardDelete || !$policy->softDeletes) {
            $sql = 'DELETE FROM ' . $table . ' WHERE ' . implode(' AND ', $whereSql);
            return new QueryPlan('delete', $table, $sql, $bindings, ['hard_delete' => true]);
        }
        $deletedAt = SqlIdentifier::assert($policy->deletedAtColumn, 'deleted_at column');
        $sql = 'UPDATE ' . $table . ' SET ' . $deletedAt . ' = ? WHERE ' . implode(' AND ', $whereSql);
        return new QueryPlan('soft_delete', $table, $sql, array_merge([date('Y-m-d H:i:s')], $bindings));
    }

    public function restoreById(TableSecurityPolicy $policy, int|string $id, array $tenantScopes = []): QueryPlan
    {
        if (!$policy->softDeletes) {
            throw new InvalidArgumentException('Restore requires a soft-delete enabled table policy.');
        }
        $table = SqlIdentifier::assert($policy->table, 'table');
        $deletedAt = SqlIdentifier::assert($policy->deletedAtColumn, 'deleted_at column');
        [$whereSql, $bindings] = $this->where([$policy->primaryKey => $id] + $tenantScopes, [$policy->primaryKey, ...array_keys($tenantScopes)]);
        $sql = 'UPDATE ' . $table . ' SET ' . $deletedAt . ' = NULL WHERE ' . implode(' AND ', $whereSql);
        return new QueryPlan('restore', $table, $sql, $bindings);
    }

    private function onlyAllowed(array $data, array $allowed, string $operation): array
    {
        $out = [];
        foreach ($data as $key => $value) {
            if (in_array($key, $allowed, true)) {
                $out[$key] = $value;
            }
        }
        return $out;
    }

    /** @return array<int,string> */
    private function allowedColumns(array $columns, array $allowed, string $operation): array
    {
        $safe = [];
        foreach ($columns as $column) {
            if (!in_array($column, $allowed, true)) {
                throw new InvalidArgumentException("Column not allowed for {$operation}: {$column}");
            }
            $safe[] = SqlIdentifier::assert((string)$column, "{$operation} column");
        }
        return $safe;
    }

    /** @return array{0:array<int,string>,1:array<int,mixed>} */
    private function where(array $filters, array $allowedColumns): array
    {
        $clauses = [];
        $bindings = [];
        foreach (DatabaseSearchFilter::normalize($filters) as $filter) {
            $col = $filter->column;
            if (!in_array($col, $allowedColumns, true)) {
                throw new InvalidArgumentException("Filter column not allowed: {$col}");
            }
            $columnSql = SqlIdentifier::assert($col, 'where column');
            switch ($filter->operator) {
                case DatabaseFilterOperator::EQ:
                    $clauses[] = $columnSql . ' = ?';
                    $bindings[] = $filter->value;
                    break;
                case DatabaseFilterOperator::NEQ:
                    $clauses[] = $columnSql . ' <> ?';
                    $bindings[] = $filter->value;
                    break;
                case DatabaseFilterOperator::IN:
                case DatabaseFilterOperator::NOT_IN:
                    $values = array_values((array)$filter->value);
                    if ($values === []) {
                        throw new InvalidArgumentException("{$filter->operator} filter requires at least one value.");
                    }
                    $placeholders = implode(', ', array_fill(0, count($values), '?'));
                    $clauses[] = $columnSql . ($filter->operator === DatabaseFilterOperator::IN ? ' IN ' : ' NOT IN ') . '(' . $placeholders . ')';
                    array_push($bindings, ...$values);
                    break;
                case DatabaseFilterOperator::BETWEEN:
                    $values = array_values((array)$filter->value);
                    if (count($values) !== 2) {
                        throw new InvalidArgumentException('between filter requires exactly two values.');
                    }
                    $clauses[] = $columnSql . ' BETWEEN ? AND ?';
                    $bindings[] = $values[0];
                    $bindings[] = $values[1];
                    break;
                case DatabaseFilterOperator::GTE:
                    $clauses[] = $columnSql . ' >= ?';
                    $bindings[] = $filter->value;
                    break;
                case DatabaseFilterOperator::LTE:
                    $clauses[] = $columnSql . ' <= ?';
                    $bindings[] = $filter->value;
                    break;
                case DatabaseFilterOperator::GT:
                    $clauses[] = $columnSql . ' > ?';
                    $bindings[] = $filter->value;
                    break;
                case DatabaseFilterOperator::LT:
                    $clauses[] = $columnSql . ' < ?';
                    $bindings[] = $filter->value;
                    break;
                case DatabaseFilterOperator::LIKE:
                    $clauses[] = $columnSql . " LIKE ? ESCAPE '\\\\'";
                    $bindings[] = '%' . $this->escapeLike((string)$filter->value) . '%';
                    break;
                case DatabaseFilterOperator::STARTS_WITH:
                    $clauses[] = $columnSql . " LIKE ? ESCAPE '\\\\'";
                    $bindings[] = $this->escapeLike((string)$filter->value) . '%';
                    break;
                case DatabaseFilterOperator::ENDS_WITH:
                    $clauses[] = $columnSql . " LIKE ? ESCAPE '\\\\'";
                    $bindings[] = '%' . $this->escapeLike((string)$filter->value);
                    break;
                case DatabaseFilterOperator::IS_NULL:
                    $clauses[] = $columnSql . ' IS NULL';
                    break;
                case DatabaseFilterOperator::IS_NOT_NULL:
                    $clauses[] = $columnSql . ' IS NOT NULL';
                    break;
                default:
                    throw new InvalidArgumentException("Unsupported database filter operator: {$filter->operator}");
            }
        }
        return [$clauses, $bindings];
    }

    private function escapeLike(string $value): string
    {
        return str_replace(['\\', '%', '_'], ['\\\\', '\\%', '\\_'], $value);
    }

    private function guard(): QueryComplexityGuard
    {
        return $this->queryGuard ??= new QueryComplexityGuard();
    }
}
