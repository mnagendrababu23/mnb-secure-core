<?php
namespace Mnb\SecurityCore\Logging;

class NullSecurityAuditTrail extends SecurityAuditTrail
{
    public function __construct()
    {
        // This class intentionally avoids touching storage. Methods are overridden below.
    }

    public function record(SecurityAuditEvent $event): array
    {
        return $event->toRecord();
    }
}
