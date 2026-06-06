<?php
namespace Mnb\SecurityCore\RateLimit;

use Mnb\SecurityCore\Contracts\RateLimiterInterface;
use PDO;

class DatabaseRateLimiter implements RateLimiterInterface
{
    public function __construct(
        private PDO $pdo,
        private string $table = 'mnb_rate_limits',
        private string $prefix = 'mnb:rate:'
    ) {}

    public function installSchema(): void
    {
        $this->pdo->exec("CREATE TABLE IF NOT EXISTS {$this->table} (rate_key VARCHAR(191) PRIMARY KEY, attempts INT NOT NULL, reset_at INT NOT NULL, updated_at INT NOT NULL)");
    }

    public function attempt(string $key, int $maxAttempts, int $decaySeconds): RateLimitResult
    {
        $this->installSchema();
        $rateKey = $this->key($key);
        $now = time();
        $this->pdo->beginTransaction();
        try {
            $statement = $this->pdo->prepare("SELECT attempts, reset_at FROM {$this->table} WHERE rate_key = ? FOR UPDATE");
            $statement->execute([$rateKey]);
            $row = $statement->fetch(PDO::FETCH_ASSOC);
            if (!$row || (int)$row['reset_at'] <= $now) {
                $attempts = 1;
                $resetAt = $now + max(1, $decaySeconds);
                $sql = "INSERT INTO {$this->table} (rate_key, attempts, reset_at, updated_at) VALUES (?, ?, ?, ?) "
                    . "ON DUPLICATE KEY UPDATE attempts = VALUES(attempts), reset_at = VALUES(reset_at), updated_at = VALUES(updated_at)";
                $this->pdo->prepare($sql)->execute([$rateKey, $attempts, $resetAt, $now]);
            } else {
                $attempts = ((int)$row['attempts']) + 1;
                $resetAt = (int)$row['reset_at'];
                $this->pdo->prepare("UPDATE {$this->table} SET attempts = ?, updated_at = ? WHERE rate_key = ?")->execute([$attempts, $now, $rateKey]);
            }
            $this->pdo->commit();
        } catch (\Throwable $e) {
            if ($this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }
            throw $e;
        }

        $retryAfter = max(0, $resetAt - $now);
        return new RateLimitResult($attempts <= $maxAttempts, max(0, $maxAttempts - $attempts), $retryAfter, $resetAt);
    }

    public function clear(string $key): void
    {
        $this->installSchema();
        $this->pdo->prepare("DELETE FROM {$this->table} WHERE rate_key = ?")->execute([$this->key($key)]);
    }

    private function key(string $key): string
    {
        return $this->prefix . hash('sha256', $key);
    }
}
