<?php
namespace Mnb\SecurityCore\Logging;

use Mnb\SecurityCore\Contracts\LoggerInterface;

class FileLogger implements LoggerInterface
{
    public function __construct(private string $file)
    {
        $dir = dirname($file);
        if (!is_dir($dir)) {
            mkdir($dir, 0775, true);
        }
    }

    public function info(string $message, array $context = []): void { $this->write('INFO', $message, $context); }
    public function warning(string $message, array $context = []): void { $this->write('WARNING', $message, $context); }
    public function error(string $message, array $context = []): void { $this->write('ERROR', $message, $context); }

    private function write(string $level, string $message, array $context): void
    {
        $safe = $this->redact($context);
        file_put_contents($this->file, json_encode([
            'time' => date('c'),
            'level' => $level,
            'message' => $message,
            'context' => $safe,
        ], JSON_UNESCAPED_SLASHES) . PHP_EOL, FILE_APPEND | LOCK_EX);
    }

    private function redact(array $context): array
    {
        foreach ($context as $key => $value) {
            if (preg_match('/password|secret|token|api[_-]?key|authorization|cookie/i', (string)$key)) {
                $context[$key] = '[redacted]';
                continue;
            }
            if (is_array($value)) {
                $context[$key] = $this->redact($value);
            } elseif (is_string($value)) {
                $context[$key] = $this->redactString($value);
            }
        }
        return $context;
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
