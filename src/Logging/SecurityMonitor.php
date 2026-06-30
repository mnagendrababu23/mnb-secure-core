<?php
namespace Mnb\SecurityCore\Logging;

use Mnb\SecurityCore\Contracts\LoggerInterface;

class SecurityMonitor
{
    public function __construct(private LoggerInterface $logger, private ?SecurityAuditTrail $audit = null) {}

    public function suspicious(string $event, array $context = []): void
    {
        $this->logger->warning('Suspicious activity: ' . $event, $context);
        $this->audit?->record(SecurityAuditEvent::sensitive($event, SecurityAuditEvent::OUTCOME_WARNING, [], [], [], $context));
    }

    public function incident(string $event, array $context = []): void
    {
        $this->logger->error('Security incident: ' . $event, $context);
        $this->audit?->record(SecurityAuditEvent::sensitive($event, SecurityAuditEvent::OUTCOME_FAILURE, [], [], [], $context));
    }
}
