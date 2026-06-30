<?php
namespace Mnb\SecurityCore\Errors;

use Throwable;

final class SafeErrorEvent
{
    /** @param array<string,mixed> $safeContext @param array<string,mixed> $technicalContext */
    public function __construct(
        private string $eventId,
        private string $requestId,
        private string $exceptionClass,
        private string $mappedCode,
        private int $publicStatus,
        private string $severity,
        private string $environment,
        private string $fingerprint,
        private array $safeContext,
        private array $technicalContext,
        private string $createdAt
    ) {}

    /** @param array<string,mixed> $mapped @param array<string,mixed> $safeContext @param array<string,mixed> $technicalContext */
    public static function fromThrowable(Throwable $throwable, ErrorContext $context, array $mapped, string $fingerprint, array $safeContext, array $technicalContext): self
    {
        return new self(
            'err_' . bin2hex(random_bytes(8)),
            $context->requestId,
            get_class($throwable),
            (string)$mapped['error_code'],
            (int)$mapped['status'],
            (string)$mapped['log_level'],
            $context->environment,
            $fingerprint,
            $safeContext,
            $technicalContext,
            date('c')
        );
    }

    public function fingerprint(): string { return $this->fingerprint; }
    public function requestId(): string { return $this->requestId; }
    public function severity(): string { return $this->severity; }
    public function mappedCode(): string { return $this->mappedCode; }
    public function publicStatus(): int { return $this->publicStatus; }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return [
            'event_id' => $this->eventId,
            'request_id' => $this->requestId,
            'exception_class' => $this->exceptionClass,
            'mapped_error_code' => $this->mappedCode,
            'public_status' => $this->publicStatus,
            'severity' => $this->severity,
            'environment' => $this->environment,
            'fingerprint' => $this->fingerprint,
            'safe_context' => $this->safeContext,
            'technical_context' => $this->technicalContext,
            'created_at' => $this->createdAt,
        ];
    }
}
