<?php
namespace Mnb\SecurityCore\Database;

use Mnb\SecurityCore\Contracts\DatabaseConnectionInterface;
use PDO;
use Throwable;

class PdoDatabaseConnection implements DatabaseConnectionInterface
{
    public function __construct(private PDO $pdo) {}

    public function fetchAll(string $sql, array $bindings = []): array
    {
        $statement = $this->pdo->prepare($sql);
        $statement->execute(array_values($bindings));
        return $statement->fetchAll(PDO::FETCH_ASSOC) ?: [];
    }

    public function fetchOne(string $sql, array $bindings = []): ?array
    {
        $statement = $this->pdo->prepare($sql);
        $statement->execute(array_values($bindings));
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        return is_array($row) ? $row : null;
    }

    public function execute(string $sql, array $bindings = []): int
    {
        $statement = $this->pdo->prepare($sql);
        $statement->execute(array_values($bindings));
        return $statement->rowCount();
    }

    public function transaction(callable $callback): mixed
    {
        $this->pdo->beginTransaction();
        try {
            $result = $callback();
            $this->pdo->commit();
            return $result;
        } catch (Throwable $e) {
            if ($this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }
            throw $e;
        }
    }

    public function lastInsertId(): string
    {
        return $this->pdo->lastInsertId();
    }
}
