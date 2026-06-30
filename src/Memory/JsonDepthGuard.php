<?php
namespace Mnb\SecurityCore\Memory;

use RuntimeException;

class JsonDepthGuard
{
    public function __construct(private int $maxDepth = 32) {}
    public static function fromConfig(array $config): self
    {
        $memory = is_array($config['memory'] ?? null) ? $config['memory'] : [];
        $payloads = is_array($memory['payloads'] ?? null) ? $memory['payloads'] : [];
        return new self((int)($payloads['max_decoded_depth'] ?? 32));
    }
    public function decode(string $json): mixed
    {
        try {
            return json_decode($json, true, $this->maxDepth, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new RuntimeException('JSON payload is invalid or too deep: ' . $e->getMessage(), 0, $e);
        }
    }
    public function maxDepth(): int { return $this->maxDepth; }
}
