<?php
namespace Mnb\SecurityCore\Logging;

use Mnb\SecurityCore\Env\SecretRedactor;

class LogDataProtector
{
    /** @param array<string,mixed> $config */
    public function __construct(private ?SecretRedactor $redactor = null, private array $config = []) {}

    /** @return array<string,mixed> */
    public function protectRecord(LogRecord $record): array
    {
        $data = $record->toArray();
        return $this->protectArray($data);
    }

    /** @param array<string,mixed> $data @return array<string,mixed> */
    public function protectArray(array $data): array
    {
        if ($this->redactor && (($this->config['use_secret_redactor'] ?? true) !== false)) {
            $data = $this->redactor->redactArray($data);
        }
        return $this->fallbackRedact($data);
    }

    /** @param array<string,mixed> $data @return array<string,mixed> */
    private function fallbackRedact(array $data): array
    {
        foreach ($data as $key => $value) {
            if (preg_match('/password|passwd|secret|token|api[_-]?key|authorization|cookie|session|csrf|otp|private[_-]?key|app[_-]?key|data[_-]?key|signed[_-]?url[_-]?key|webhook[_-]?secret/i', (string)$key)) {
                $data[$key] = '[redacted]';
                continue;
            }
            if (is_array($value)) {
                $data[$key] = $this->fallbackRedact($value);
            } elseif (is_string($value)) {
                $data[$key] = $this->redactString($value);
            }
        }
        return $data;
    }

    private function redactString(string $value): string
    {
        $patterns = [
            '/(password\s*[=:]\s*)[^\s,;]+/i',
            '/(secret\s*[=:]\s*)[^\s,;]+/i',
            '/(token\s*[=:]\s*)[^\s,;]+/i',
            '/(api[_-]?key\s*[=:]\s*)[^\s,;]+/i',
            '/(Bearer\s+)[A-Za-z0-9._\-]+/i',
            '/(APP_KEY\s*[=:]\s*)[^\s,;]+/i',
            '/(DATA_KEY\s*[=:]\s*)[^\s,;]+/i',
        ];
        return preg_replace($patterns, '$1[redacted]', $value) ?? $value;
    }
}
