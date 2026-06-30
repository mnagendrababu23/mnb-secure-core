<?php
namespace Mnb\SecurityCore\Memory;

use RuntimeException;

class StreamGuard
{
    public function __construct(private StreamBudget $budget) {}
    public static function fromConfig(array $config): self
    {
        $memory = is_array($config['memory'] ?? null) ? $config['memory'] : [];
        return new self(StreamBudget::fromArray(is_array($memory['streams'] ?? null) ? $memory['streams'] : []));
    }
    public function budget(): StreamBudget { return $this->budget; }

    public function assertCanRead(int $bytesRead, int $additionalBytes = 0): void
    {
        if ($bytesRead + max(0, $additionalBytes) > $this->budget->maxReadBytes()) {
            throw new RuntimeException('Stream read budget exceeded.');
        }
    }

    public function assertCanWrite(int $bytesWritten, int $additionalBytes = 0): void
    {
        if ($bytesWritten + max(0, $additionalBytes) > $this->budget->maxWriteBytes()) {
            throw new RuntimeException('Stream write budget exceeded.');
        }
    }

    public function plan(int $bytes, string $mode = 'read'): array
    {
        $limit = $mode === 'write' ? $this->budget->maxWriteBytes() : $this->budget->maxReadBytes();
        $chunks = (int)ceil(max(0, $bytes) / $this->budget->bufferSize());
        return ['passed' => $bytes <= $limit, 'mode' => $mode, 'bytes' => $bytes, 'limit_bytes' => $limit, 'buffer_size' => $this->budget->bufferSize(), 'estimated_chunks' => $chunks];
    }
}
