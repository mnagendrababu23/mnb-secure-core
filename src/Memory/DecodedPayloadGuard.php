<?php
namespace Mnb\SecurityCore\Memory;

class DecodedPayloadGuard
{
    public function __construct(private PayloadSizeGuard $sizeGuard, private ArrayDepthGuard $depthGuard) {}
    public static function fromConfig(array $config): self
    {
        $memory = is_array($config['memory'] ?? null) ? $config['memory'] : [];
        $payloads = is_array($memory['payloads'] ?? null) ? $memory['payloads'] : [];
        return new self(PayloadSizeGuard::fromConfig($config), new ArrayDepthGuard((int)($payloads['max_decoded_depth'] ?? 32)));
    }
    public function assertSafe(mixed $payload): void
    {
        if (is_string($payload)) { $this->sizeGuard->assertString($payload); }
        if (is_array($payload)) { $this->sizeGuard->assertArray($payload); $this->depthGuard->assertWithinDepth($payload); }
    }
}
