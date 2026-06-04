<?php
namespace Mnb\SecurityCore\Contracts;

interface DatabaseConnectionInterface
{
    /** @return array<int,array<string,mixed>> */
    public function fetchAll(string $sql, array $bindings = []): array;

    /** @return array<string,mixed>|null */
    public function fetchOne(string $sql, array $bindings = []): ?array;

    public function execute(string $sql, array $bindings = []): int;

    /** @template T @param callable():T $callback @return T */
    public function transaction(callable $callback): mixed;

    public function lastInsertId(): string;
}
