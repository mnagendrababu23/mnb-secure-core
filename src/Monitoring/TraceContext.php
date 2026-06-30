<?php
namespace Mnb\SecurityCore\Monitoring;

use Mnb\SecurityCore\Http\Request;

class TraceContext
{
    /** @param array<string,mixed> $attributes */
    public function __construct(
        public readonly string $requestId,
        public readonly ?string $traceId = null,
        public readonly ?string $userId = null,
        public readonly ?string $tenantId = null,
        public readonly array $attributes = []
    ) {}

    public static function fromRequest(Request $request): self
    {
        $requestId = (string)($request->attribute('request_id') ?: $request->header('x-request-id') ?: self::newId());
        return new self(
            $requestId,
            (string)($request->header('traceparent') ?: $requestId),
            ($request->attribute('auth_user_id') !== null ? (string)$request->attribute('auth_user_id') : null),
            ($request->attribute('school_id') !== null ? (string)$request->attribute('school_id') : null),
            [
                'method' => $request->method(),
                'path' => $request->path(),
                'ip' => $request->ip(),
            ]
        );
    }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return array_filter([
            'request_id' => $this->requestId,
            'trace_id' => $this->traceId,
            'user_id' => $this->userId,
            'tenant_id' => $this->tenantId,
            'attributes' => $this->attributes,
        ], fn($value) => $value !== null && $value !== []);
    }

    private static function newId(): string
    {
        try { return bin2hex(random_bytes(12)); } catch (\Throwable) { return str_replace('.', '', uniqid('trace_', true)); }
    }
}
