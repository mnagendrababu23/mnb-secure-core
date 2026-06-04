<?php
namespace Mnb\SecurityCore\Database;

use Mnb\SecurityCore\Contracts\DatabaseConnectionInterface;

class DryRunDatabaseConnection implements DatabaseConnectionInterface
{
    /** @var array<int,array{type:string,sql:string,bindings:array}> */
    private array $queries = [];

    public function fetchAll(string $sql, array $bindings = []): array
    {
        $this->queries[] = ['type' => 'fetchAll', 'sql' => $sql, 'bindings' => array_values($bindings)];
        return [];
    }

    public function fetchOne(string $sql, array $bindings = []): ?array
    {
        $this->queries[] = ['type' => 'fetchOne', 'sql' => $sql, 'bindings' => array_values($bindings)];
        return null;
    }

    public function execute(string $sql, array $bindings = []): int
    {
        $this->queries[] = ['type' => 'execute', 'sql' => $sql, 'bindings' => array_values($bindings)];
        return 1;
    }

    public function transaction(callable $callback): mixed
    {
        $this->queries[] = ['type' => 'transaction.begin', 'sql' => '', 'bindings' => []];
        $result = $callback();
        $this->queries[] = ['type' => 'transaction.commit', 'sql' => '', 'bindings' => []];
        return $result;
    }

    public function lastInsertId(): string
    {
        return 'dry-run-id';
    }

    /** @return array<int,array{type:string,sql:string,bindings:array}> */
    public function queries(): array
    {
        return $this->queries;
    }

    public function lastQuery(): ?array
    {
        return $this->queries ? $this->queries[array_key_last($this->queries)] : null;
    }
}
