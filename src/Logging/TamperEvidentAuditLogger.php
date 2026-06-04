<?php
namespace Mnb\SecurityCore\Logging;

class TamperEvidentAuditLogger
{
    public function __construct(private string $file)
    {
        $dir = dirname($file);
        if (!is_dir($dir)) {
            mkdir($dir, 0775, true);
        }
        if (!is_file($file)) {
            file_put_contents($file, '');
        }
    }

    public function record(string $action, array $actor = [], array $target = [], array $meta = []): array
    {
        $previous = $this->lastHash();
        $entry = [
            'time' => date('c'),
            'action' => $action,
            'actor' => $this->redact($actor),
            'target' => $target,
            'meta' => $this->redact($meta),
            'previous_hash' => $previous,
        ];
        $entry['hash'] = $this->hashEntry($entry);
        file_put_contents($this->file, json_encode($entry, JSON_UNESCAPED_SLASHES) . PHP_EOL, FILE_APPEND | LOCK_EX);
        return $entry;
    }

    public function verify(): bool
    {
        $previous = '';
        foreach (file($this->file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
            $entry = json_decode($line, true);
            if (!is_array($entry) || ($entry['previous_hash'] ?? '') !== $previous) {
                return false;
            }
            $hash = $entry['hash'] ?? '';
            unset($entry['hash']);
            if (!hash_equals($hash, $this->hashEntry($entry))) {
                return false;
            }
            $previous = $hash;
        }
        return true;
    }

    private function lastHash(): string
    {
        $lines = file($this->file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
        if (!$lines) {
            return '';
        }
        $last = json_decode(end($lines), true);
        return is_array($last) ? (string)($last['hash'] ?? '') : '';
    }

    private function hashEntry(array $entry): string
    {
        return hash('sha256', json_encode($entry, JSON_UNESCAPED_SLASHES));
    }

    private function redact(array $context): array
    {
        foreach ($context as $key => $value) {
            if (preg_match('/password|secret|token|key/i', (string)$key)) {
                $context[$key] = '[redacted]';
            }
        }
        return $context;
    }
}
