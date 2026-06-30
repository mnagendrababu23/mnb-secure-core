<?php
namespace Mnb\SecurityCore\Errors;

use Mnb\SecurityCore\Contracts\LoggerInterface;

final class ErrorAlertDispatcher
{
    public function __construct(private ?LoggerInterface $logger = null) {}

    /** @param array<string,mixed> $event */
    public function dispatch(array $event, string $reason = 'error_escalation'): array
    {
        $payload = [
            'dispatched' => true,
            'reason' => $reason,
            'request_id' => $event['request_id'] ?? null,
            'fingerprint' => $event['fingerprint'] ?? null,
            'mapped_error_code' => $event['mapped_error_code'] ?? null,
            'public_status' => $event['public_status'] ?? null,
        ];
        if ($this->logger) {
            $this->logger->warning('Security error escalation triggered', $payload);
        }
        return $payload;
    }
}
