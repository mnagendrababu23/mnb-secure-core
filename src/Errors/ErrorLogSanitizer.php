<?php
namespace Mnb\SecurityCore\Errors;

final class ErrorLogSanitizer
{
    public function __construct(private ErrorPolicy $policy) {}

    public function sanitize(mixed $value): mixed
    {
        if (!$this->policy->redactionEnabled()) {
            return $value;
        }
        if (is_array($value)) {
            $out = [];
            foreach ($value as $key => $item) {
                if ($this->isSensitiveKey((string)$key)) {
                    $out[$key] = $this->policy->redactionReplacement();
                    continue;
                }
                $out[$key] = $this->sanitize($item);
            }
            return $out;
        }
        if (is_string($value)) {
            return $this->sanitizeString($value);
        }
        return $value;
    }

    public function sanitizeString(string $value): string
    {
        $replacement = $this->policy->redactionReplacement();
        $patterns = [
            '/(password\s*[=:]\s*)[^\s,;]+/i',
            '/(passwd\s*[=:]\s*)[^\s,;]+/i',
            '/(secret\s*[=:]\s*)[^\s,;]+/i',
            '/(token\s*[=:]\s*)[^\s,;]+/i',
            '/(api[_-]?key\s*[=:]\s*)[^\s,;]+/i',
            '/(authorization\s*[=:]\s*)[^\r\n,;]+/i',
            '/(cookie\s*[=:]\s*)[^\r\n]+/i',
            '/(Bearer\s+)[A-Za-z0-9._\-~+\/]+=*/i',
            '/(APP_KEY\s*[=:]\s*)[^\s,;]+/i',
            '/(DATA_KEY\s*[=:]\s*)[^\s,;]+/i',
            '/(DB_PASSWORD\s*[=:]\s*)[^\s,;]+/i',
        ];
        $value = preg_replace($patterns, '$1' . $replacement, $value) ?? $value;
        if ($this->policy->redactPii()) {
            $value = preg_replace('/[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}/i', $replacement, $value) ?? $value;
            $value = preg_replace('/\b(?:\+?\d[\d\s().-]{7,}\d)\b/', $replacement, $value) ?? $value;
        }
        if ($this->policy->redactPaths()) {
            $value = preg_replace('#(?:[A-Za-z]:\\\\|/)(?:[^\s"\']+[\\\\/])*[^\s"\']+#', '[path]', $value) ?? $value;
        }
        return $value;
    }

    private function isSensitiveKey(string $key): bool
    {
        return (bool)preg_match('/password|passwd|secret|token|api[_-]?key|authorization|cookie|session|csrf|otp|private[_-]?key|app[_-]?key|data[_-]?key|db[_-]?password/i', $key);
    }
}
