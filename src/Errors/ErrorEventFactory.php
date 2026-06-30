<?php
namespace Mnb\SecurityCore\Errors;

use Throwable;

final class ErrorEventFactory
{
    public function __construct(
        private ErrorPolicy $policy,
        private ExceptionMapper $mapper,
        private ErrorFingerprint $fingerprint,
        private ErrorLogSanitizer $sanitizer,
        private StackTraceSanitizer $stackSanitizer
    ) {}

    /** @param array<string,mixed> $extra */
    public function create(Throwable $throwable, ErrorContext $context, array $extra = []): SafeErrorEvent
    {
        $mapped = $this->mapper->map($throwable);
        $fingerprint = $this->fingerprint->create($throwable, $context, $mapped, $extra);
        $safe = $this->sanitizer->sanitize([
            'path' => $extra['path'] ?? null,
            'method' => $extra['method'] ?? null,
            'ip' => $extra['ip'] ?? null,
            'error_code' => $mapped['error_code'],
            'status' => $mapped['status'],
        ]);
        $technical = $this->sanitizer->sanitize($context->logContext($throwable, $extra + [
            'mapped_error_code' => $mapped['error_code'],
            'public_status' => $mapped['status'],
        ]));
        if ($this->policy->includeStackTrace()) {
            $technical['stack'] = $this->stackSanitizer->sanitize($throwable);
        }
        return SafeErrorEvent::fromThrowable($throwable, $context, $mapped, $fingerprint, $safe, $technical);
    }
}
