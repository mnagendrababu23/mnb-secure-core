<?php
namespace Mnb\SecurityCore\Env;

class SecretRedactor
{
    /** @param array<int,string> $extraKeys */
    public function __construct(
        private string $replacement = '[redacted]',
        private int $showLast = 0,
        private array $extraKeys = []
    ) {}

    public function redactValue(mixed $value): mixed
    {
        if (!is_scalar($value) && $value !== null) {
            return $this->replacement;
        }
        $string = (string)$value;
        if ($this->showLast > 0 && strlen($string) > $this->showLast) {
            return $this->replacement . ':' . substr($string, -$this->showLast);
        }
        return $this->replacement;
    }

    /** @param array<string|int,mixed> $data @return array<string|int,mixed> */
    public function redactArray(array $data): array
    {
        $out = [];
        foreach ($data as $key => $value) {
            $keyString = (string)$key;
            if ($this->isSensitiveKey($keyString)) {
                $out[$key] = $this->redactValue($value);
                continue;
            }
            $out[$key] = is_array($value) ? $this->redactArray($value) : $this->redactText((string)$value, preserveNonSecret: true);
        }
        return $out;
    }

    public function redactText(string $text, bool $preserveNonSecret = false): string
    {
        $patterns = [
            '/(Authorization:\s*Bearer\s+)[A-Za-z0-9._\-+=\/]+/i' => '$1' . $this->replacement,
            '/((?:api[_-]?key|secret|password|token|private[_-]?key)\s*[=:]\s*)["\']?[^\s"\']{8,}/i' => '$1' . $this->replacement,
            '/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/s' => $this->replacement,
        ];
        $redacted = $text;
        foreach ($patterns as $pattern => $replace) {
            $redacted = preg_replace($pattern, $replace, $redacted) ?? $redacted;
        }
        return $preserveNonSecret ? $redacted : ($redacted === $text ? $text : $redacted);
    }

    public function isSensitiveKey(string $key): bool
    {
        $normalized = strtolower(str_replace(['-', '.', ' '], '_', $key));
        foreach (array_merge($this->extraKeys, ['password', 'passwd', 'pwd', 'secret', 'token', 'api_key', 'apikey', 'authorization', 'cookie', 'session', 'csrf', 'otp', 'private_key', 'app_key', 'data_key', 'signed_url_key', 'webhook_secret']) as $needle) {
            $needle = strtolower(str_replace(['-', '.', ' '], '_', $needle));
            if ($needle !== '' && str_contains($normalized, $needle)) {
                return true;
            }
        }
        return false;
    }
}
