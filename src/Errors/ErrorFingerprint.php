<?php
namespace Mnb\SecurityCore\Errors;

use Throwable;

final class ErrorFingerprint
{
    public function __construct(private ErrorPolicy $policy, private ?ErrorLogSanitizer $sanitizer = null) {
        $this->sanitizer ??= new ErrorLogSanitizer($policy);
    }

    /** @param array<string,mixed> $mapped @param array<string,mixed> $extra */
    public function create(Throwable $throwable, ErrorContext $context, array $mapped, array $extra = []): string
    {
        if (!$this->policy->fingerprintingEnabled()) {
            return hash('sha256', $context->requestId);
        }
        $route = (string)($extra['route'] ?? $extra['path'] ?? 'unknown');
        $message = $this->sanitizer->sanitizeString($throwable->getMessage());
        $parts = [get_class($throwable), (string)$mapped['error_code'], $route, substr(hash('sha256', $message), 0, 16)];
        return 'fp_' . substr(hash('sha256', implode('|', $parts)), 0, 32);
    }
}
