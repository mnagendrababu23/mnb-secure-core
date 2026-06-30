<?php
namespace Mnb\SecurityCore\Auth\Stores;

use Mnb\SecurityCore\Contracts\TokenStoreInterface;
use Mnb\SecurityCore\Database\SqlIdentifier;
use PDO;

class DatabaseTokenStore implements TokenStoreInterface
{
    public function __construct(
        private PDO $pdo,
        private string $table = 'mnb_api_tokens'
    ) {
        $this->table = SqlIdentifier::assert($this->table, 'token table');
    }

    public function installSchema(): void
    {
        $this->pdo->exec("CREATE TABLE IF NOT EXISTS {$this->table} (token_hash CHAR(64) PRIMARY KEY, user_id VARCHAR(191) NOT NULL, scopes TEXT NULL, device_id VARCHAR(191) NULL, device_name VARCHAR(191) NULL, expires_at INT NOT NULL, created_at INT NOT NULL, revoked_at INT NULL, last_used_at INT NULL, last_ip VARCHAR(64) NULL, last_user_agent VARCHAR(255) NULL)");
    }

    public function store(array $record): void
    {
        $this->installSchema();
        $sql = "INSERT INTO {$this->table} (token_hash, user_id, scopes, device_id, device_name, expires_at, created_at, revoked_at, last_used_at, last_ip, last_user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            . "ON DUPLICATE KEY UPDATE user_id = VALUES(user_id), scopes = VALUES(scopes), device_id = VALUES(device_id), device_name = VALUES(device_name), expires_at = VALUES(expires_at), revoked_at = VALUES(revoked_at), last_used_at = VALUES(last_used_at), last_ip = VALUES(last_ip), last_user_agent = VALUES(last_user_agent)";
        $this->pdo->prepare($sql)->execute([
            $record['token_hash'],
            (string)$record['user_id'],
            json_encode($record['scopes'] ?? [], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
            $record['device_id'] ?? null,
            $record['device_name'] ?? null,
            (int)$record['expires_at'],
            (int)($record['created_at'] ?? time()),
            $record['revoked_at'] ?? null,
            $record['last_used_at'] ?? null,
            $record['last_ip'] ?? null,
            isset($record['last_user_agent']) ? substr((string)$record['last_user_agent'], 0, 255) : null,
        ]);
    }

    public function findByHash(string $tokenHash): ?array
    {
        $this->installSchema();
        $statement = $this->pdo->prepare("SELECT * FROM {$this->table} WHERE token_hash = ? LIMIT 1");
        $statement->execute([$tokenHash]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        if (!$row) {
            return null;
        }
        $row['scopes'] = json_decode((string)($row['scopes'] ?? '[]'), true) ?: [];
        foreach (['expires_at', 'created_at', 'revoked_at', 'last_used_at'] as $field) {
            $row[$field] = $row[$field] === null ? null : (int)$row[$field];
        }
        return $row;
    }

    public function revoke(string $tokenHash): void
    {
        $this->installSchema();
        $this->pdo->prepare("UPDATE {$this->table} SET revoked_at = ? WHERE token_hash = ?")->execute([time(), $tokenHash]);
    }

    public function revokeUserTokens(int|string $userId): void
    {
        $this->installSchema();
        $this->pdo->prepare("UPDATE {$this->table} SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL")->execute([time(), (string)$userId]);
    }

    public function touch(string $tokenHash, ?string $ip = null, ?string $userAgent = null): void
    {
        $this->installSchema();
        $this->pdo->prepare("UPDATE {$this->table} SET last_used_at = ?, last_ip = ?, last_user_agent = ? WHERE token_hash = ?")
            ->execute([time(), $ip, $userAgent ? substr($userAgent, 0, 255) : null, $tokenHash]);
    }
}
