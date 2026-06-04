<?php
namespace Mnb\SecurityCore\Auth\Stores;

use Mnb\SecurityCore\Contracts\TokenStoreInterface;

class FileTokenStore implements TokenStoreInterface
{
    public function __construct(private string $file)
    {
        $dir = dirname($file);
        if (!is_dir($dir)) {
            mkdir($dir, 0775, true);
        }
        if (!is_file($file)) {
            file_put_contents($file, json_encode([]));
        }
    }

    public function store(array $record): void
    {
        $this->mutate(function (array $records) use ($record) {
            $records[$record['token_hash']] = $record;
            return $records;
        });
    }

    public function findByHash(string $tokenHash): ?array
    {
        $records = $this->read();
        return $records[$tokenHash] ?? null;
    }

    public function revoke(string $tokenHash): void
    {
        $this->mutate(function (array $records) use ($tokenHash) {
            if (isset($records[$tokenHash])) {
                $records[$tokenHash]['revoked_at'] = time();
            }
            return $records;
        });
    }

    public function revokeUserTokens(int|string $userId): void
    {
        $this->mutate(function (array $records) use ($userId) {
            foreach ($records as &$record) {
                if ((string)$record['user_id'] === (string)$userId) {
                    $record['revoked_at'] = time();
                }
            }
            return $records;
        });
    }

    public function touch(string $tokenHash, ?string $ip = null, ?string $userAgent = null): void
    {
        $this->mutate(function (array $records) use ($tokenHash, $ip, $userAgent) {
            if (isset($records[$tokenHash])) {
                $records[$tokenHash]['last_used_at'] = time();
                $records[$tokenHash]['last_ip'] = $ip;
                $records[$tokenHash]['last_user_agent'] = $userAgent;
            }
            return $records;
        });
    }

    private function read(): array
    {
        $json = file_get_contents($this->file);
        $data = json_decode($json ?: '[]', true);
        return is_array($data) ? $data : [];
    }

    private function mutate(callable $callback): void
    {
        $handle = fopen($this->file, 'c+');
        if (!$handle) {
            throw new \RuntimeException('Unable to open token store');
        }
        flock($handle, LOCK_EX);
        $json = stream_get_contents($handle) ?: '[]';
        $records = json_decode($json, true);
        $records = is_array($records) ? $records : [];
        $records = $callback($records);
        ftruncate($handle, 0);
        rewind($handle);
        fwrite($handle, json_encode($records, JSON_PRETTY_PRINT));
        fflush($handle);
        flock($handle, LOCK_UN);
        fclose($handle);
    }
}
