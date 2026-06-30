<?php
namespace Mnb\SecurityCore\Cache;

use Mnb\SecurityCore\Contracts\CacheInterface;
use Mnb\SecurityCore\Database\SqlIdentifier;
use PDO;

class DatabaseCache implements CacheInterface
{
    public function __construct(
        private PDO $pdo,
        private string $table = 'mnb_cache',
        private string $prefix = 'mnb:cache:'
    ) {
        $this->table = SqlIdentifier::assert($this->table, 'cache table');
    }

    public function installSchema(): void
    {
        $this->pdo->exec("CREATE TABLE IF NOT EXISTS {$this->table} (cache_key VARCHAR(191) PRIMARY KEY, cache_value MEDIUMTEXT NOT NULL, expires_at INT NOT NULL, updated_at INT NOT NULL)");
    }

    public function get(string $key, mixed $default = null): mixed
    {
        $statement = $this->pdo->prepare("SELECT cache_value, expires_at FROM {$this->table} WHERE cache_key = ? LIMIT 1");
        $statement->execute([$this->key($key)]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        if (!$row) {
            return $default;
        }
        if ((int)$row['expires_at'] < time()) {
            $this->forget($key);
            return $default;
        }
        $decoded = json_decode((string)$row['cache_value'], true);
        return is_array($decoded) && array_key_exists('data', $decoded) ? $decoded['data'] : $default;
    }

    public function put(string $key, mixed $value, int $ttlSeconds): void
    {
        $this->installSchema();
        $cacheKey = $this->key($key);
        $payload = json_encode(['data' => $value], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        $now = time();
        $expiresAt = $now + max(1, $ttlSeconds);
        $sql = "INSERT INTO {$this->table} (cache_key, cache_value, expires_at, updated_at) VALUES (?, ?, ?, ?) "
            . "ON DUPLICATE KEY UPDATE cache_value = VALUES(cache_value), expires_at = VALUES(expires_at), updated_at = VALUES(updated_at)";
        $this->pdo->prepare($sql)->execute([$cacheKey, $payload, $expiresAt, $now]);
    }

    public function forget(string $key): void
    {
        $this->pdo->prepare("DELETE FROM {$this->table} WHERE cache_key = ?")->execute([$this->key($key)]);
    }

    public function has(string $key): bool
    {
        return $this->get($key, null) !== null;
    }

    private function key(string $key): string
    {
        return $this->prefix . hash('sha256', $key);
    }
}
