<?php
namespace Mnb\SecurityCore\Queue;

final class JobPayloadProtector
{
    public function __construct(private array $policy = [], private JobPayloadRedactor $redactor = new JobPayloadRedactor()) {}
    public static function fromConfig(array $config): self { $queue = is_array($config['queue'] ?? null) ? $config['queue'] : []; return new self(is_array($queue['payload_security'] ?? null) ? $queue['payload_security'] : []); }

    public function inspect(array $payload): array
    {
        $redacted = $this->redactor->redact($payload);
        $json = json_encode($redacted, JSON_UNESCAPED_SLASHES) ?: '';
        $maxDepth = (int)($this->policy['max_depth'] ?? 16);
        $maxStringBytes = (int)($this->policy['max_string_bytes'] ?? 8192);
        $findings = [];
        if ($this->containsRawSecret($payload) && !empty($this->policy['deny_tokens'])) { $findings[] = 'secret_like_payload_field'; }
        if ($this->maxDepth($payload) > $maxDepth) { $findings[] = 'payload_too_deep'; }
        if ($this->hasLargeString($payload, $maxStringBytes)) { $findings[] = 'payload_string_too_large'; }
        if (!empty($this->policy['deny_raw_filesystem_paths']) && preg_match('#(/[a-zA-Z0-9._-]+){3,}#', $json)) { $findings[] = 'raw_filesystem_path'; }
        return ['passed'=>empty($findings), 'findings'=>$findings, 'redacted_payload'=>$redacted, 'bytes'=>strlen($json), 'redacted'=>($redacted !== $payload)];
    }

    public function protect(array $payload, bool $blockOnFindings = true): array
    {
        $report = $this->inspect($payload);
        if (!$report['passed'] && $blockOnFindings) { throw new \InvalidArgumentException('Unsafe queue payload: ' . implode(',', $report['findings'])); }
        return $report['redacted_payload'];
    }

    private function containsRawSecret(array $payload): bool { return $this->redactor->redact($payload) !== $payload; }
    private function maxDepth(mixed $value, int $depth = 0): int { if (!is_array($value) || $value === []) { return $depth; } return max(array_map(fn($v) => $this->maxDepth($v, $depth + 1), $value)); }
    private function hasLargeString(mixed $value, int $limit): bool { if (is_string($value)) { return strlen($value) > $limit; } if (is_array($value)) { foreach ($value as $v) { if ($this->hasLargeString($v, $limit)) { return true; } } } return false; }
}
