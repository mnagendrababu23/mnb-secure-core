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
        $event = SecurityAuditEvent::make(
            $this->categoryFromAction($action),
            $action,
            SecurityAuditEvent::OUTCOME_INFO,
            SecurityAuditEvent::SEVERITY_INFO,
            $actor,
            $target,
            [],
            $meta
        );
        return $this->recordEvent($event);
    }

    public function recordEvent(SecurityAuditEvent $event): array
    {
        $previous = $this->lastHash();
        $entry = $this->redact($event->toRecord());
        $entry['previous_hash'] = $previous;
        $entry['hash'] = $this->hashEntry($entry);
        file_put_contents($this->file, json_encode($entry, JSON_UNESCAPED_SLASHES) . PHP_EOL, FILE_APPEND | LOCK_EX);
        return $entry;
    }

    public function verify(): bool
    {
        return $this->verifyDetailed()['valid'];
    }

    /** @return array{valid:bool,entries:int,failed_line:int|null,error:string|null} */
    public function verifyDetailed(): array
    {
        $previous = '';
        $lineNumber = 0;
        foreach (file($this->file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
            $lineNumber++;
            $entry = json_decode($line, true);
            if (!is_array($entry)) {
                return ['valid' => false, 'entries' => $lineNumber - 1, 'failed_line' => $lineNumber, 'error' => 'invalid_json'];
            }
            if (($entry['previous_hash'] ?? '') !== $previous) {
                return ['valid' => false, 'entries' => $lineNumber - 1, 'failed_line' => $lineNumber, 'error' => 'previous_hash_mismatch'];
            }
            $hash = $entry['hash'] ?? '';
            unset($entry['hash']);
            if (!is_string($hash) || !hash_equals($hash, $this->hashEntry($entry))) {
                return ['valid' => false, 'entries' => $lineNumber - 1, 'failed_line' => $lineNumber, 'error' => 'hash_mismatch'];
            }
            $previous = $hash;
        }
        return ['valid' => true, 'entries' => $lineNumber, 'failed_line' => null, 'error' => null];
    }

    /** @return list<array<string,mixed>> */
    public function read(?int $limit = 100, ?string $category = null): array
    {
        $entries = [];
        foreach (file($this->file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
            $entry = json_decode($line, true);
            if (!is_array($entry)) {
                continue;
            }
            if ($category !== null && ($entry['category'] ?? null) !== $category) {
                continue;
            }
            $entries[] = $entry;
        }
        if ($limit !== null && $limit > 0) {
            return array_slice($entries, -$limit);
        }
        return $entries;
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

    private function categoryFromAction(string $action): string
    {
        $prefix = strtolower(strtok($action, '.:') ?: $action);
        return match ($prefix) {
            'auth', 'login', 'logout', 'session' => SecurityAuditEvent::CATEGORY_AUTH,
            'token', 'api_token' => SecurityAuditEvent::CATEGORY_TOKEN,
            'upload', 'file' => SecurityAuditEvent::CATEGORY_UPLOAD,
            'admin' => SecurityAuditEvent::CATEGORY_ADMIN,
            'db', 'database', 'schema' => SecurityAuditEvent::CATEGORY_DATABASE,
            'secret', 'sensitive', 'privacy' => SecurityAuditEvent::CATEGORY_SENSITIVE,
            default => SecurityAuditEvent::CATEGORY_SYSTEM,
        };
    }

    /** @param mixed $value @return mixed */
    private function redact(mixed $value): mixed
    {
        if (!is_array($value)) {
            return is_string($value) ? $this->redactString($value) : $value;
        }

        foreach ($value as $key => $item) {
            if (preg_match('/password|passwd|secret|token|api[_-]?key|authorization|cookie|session|csrf|private[_-]?key/i', (string)$key)) {
                $value[$key] = '[redacted]';
                continue;
            }
            $value[$key] = $this->redact($item);
        }
        return $value;
    }

    private function redactString(string $value): string
    {
        $patterns = [
            '/(password\s*[=:]\s*)[^\s,;]+/i',
            '/(secret\s*[=:]\s*)[^\s,;]+/i',
            '/(token\s*[=:]\s*)[^\s,;]+/i',
            '/(api[_-]?key\s*[=:]\s*)[^\s,;]+/i',
            '/(Bearer\s+)[A-Za-z0-9._\-]+/i',
        ];
        return preg_replace($patterns, '$1[redacted]', $value) ?? $value;
    }
}
