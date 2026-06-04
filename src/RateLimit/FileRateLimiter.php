<?php
namespace Mnb\SecurityCore\RateLimit;

use Mnb\SecurityCore\Contracts\RateLimiterInterface;

class FileRateLimiter implements RateLimiterInterface
{
    public function __construct(private string $path)
    {
        if (!is_dir($path)) {
            mkdir($path, 0775, true);
        }
    }

    public function attempt(string $key, int $maxAttempts, int $decaySeconds): RateLimitResult
    {
        $file = $this->file($key);
        $handle = fopen($file, 'c+');
        if (!$handle) {
            throw new \RuntimeException('Unable to open rate limit file');
        }
        flock($handle, LOCK_EX);
        $raw = stream_get_contents($handle) ?: '{}';
        $record = json_decode($raw, true);
        $record = is_array($record) ? $record : [];
        $now = time();
        if (($record['reset_at'] ?? 0) <= $now) {
            $record = ['attempts' => 0, 'reset_at' => $now + $decaySeconds];
        }
        $record['attempts']++;
        $allowed = $record['attempts'] <= $maxAttempts;
        $remaining = max(0, $maxAttempts - $record['attempts']);
        ftruncate($handle, 0);
        rewind($handle);
        fwrite($handle, json_encode($record));
        fflush($handle);
        flock($handle, LOCK_UN);
        fclose($handle);

        return new RateLimitResult($allowed, $remaining, max(0, $record['reset_at'] - $now), $record['reset_at']);
    }

    public function clear(string $key): void
    {
        @unlink($this->file($key));
    }

    private function file(string $key): string
    {
        return rtrim($this->path, '/') . '/' . hash('sha256', $key) . '.rl.json';
    }
}
