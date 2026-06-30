<?php
namespace Mnb\SecurityCore\Queue;

final class JobPayloadRedactor
{
    private array $secretKeys = ['password','passwd','password_hash','token','api_key','secret','authorization','cookie'];
    public function redact(array $payload): array
    {
        $out = [];
        foreach ($payload as $key => $value) {
            $lower = strtolower((string)$key);
            $sensitive = false;
            foreach ($this->secretKeys as $needle) { if (str_contains($lower, $needle)) { $sensitive = true; break; } }
            if ($sensitive) { $out[$key] = '[redacted]'; continue; }
            $out[$key] = is_array($value) ? $this->redact($value) : $value;
        }
        return $out;
    }
}
