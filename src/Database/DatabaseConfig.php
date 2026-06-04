<?php
namespace Mnb\SecurityCore\Database;

use PDO;

class DatabaseConfig
{
    public function __construct(
        public readonly string $dsn,
        public readonly ?string $username = null,
        public readonly ?string $password = null,
        public readonly array $options = []
    ) {}

    public static function fromArray(array $config): self
    {
        $driver = (string)($config['driver'] ?? 'mysql');
        if (isset($config['dsn'])) {
            $dsn = (string)$config['dsn'];
        } elseif ($driver === 'sqlite') {
            $dsn = 'sqlite:' . (string)($config['database'] ?? ':memory:');
        } else {
            $host = (string)($config['host'] ?? '127.0.0.1');
            $port = (string)($config['port'] ?? '3306');
            $db = (string)($config['database'] ?? '');
            $charset = (string)($config['charset'] ?? 'utf8mb4');
            $dsn = "{$driver}:host={$host};port={$port};dbname={$db};charset={$charset}";
        }

        return new self(
            $dsn,
            $config['username'] ?? null,
            $config['password'] ?? null,
            (array)($config['options'] ?? [])
        );
    }

    public function securePdoOptions(): array
    {
        return $this->options + [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
            PDO::ATTR_STRINGIFY_FETCHES => false,
        ];
    }
}
