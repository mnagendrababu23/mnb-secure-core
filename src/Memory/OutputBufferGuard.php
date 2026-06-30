<?php
namespace Mnb\SecurityCore\Memory;

use RuntimeException;

class OutputBufferGuard
{
    public function __construct(private ResponseSizeBudget $budget) {}
    public static function fromConfig(array $config): self
    {
        $memory = is_array($config['memory'] ?? null) ? $config['memory'] : [];
        return new self(ResponseSizeBudget::fromArray(is_array($memory['output_buffers'] ?? null) ? $memory['output_buffers'] : []));
    }
    public function assertSafe(string $buffer): void
    {
        if (strlen($buffer) > $this->budget->maxBufferBytes()) { throw new RuntimeException('Output buffer size limit exceeded.'); }
    }
    public function check(string $buffer): array
    {
        $bytes = strlen($buffer);
        return ['passed' => $bytes <= $this->budget->maxBufferBytes(), 'bytes' => $bytes, 'limit_bytes' => $this->budget->maxBufferBytes()];
    }
}
