<?php
namespace Mnb\SecurityCore\Errors;

final class ErrorAuditEvents
{
    public const HANDLED = 'error.handled';
    public const RESPONSE_CREATED = 'error.response_created';
    public const LOG_SANITIZED = 'error.log_sanitized';
    public const STACK_SANITIZED = 'error.stack_sanitized';
    public const VALIDATION_NORMALIZED = 'error.validation_normalized';
    public const FINGERPRINT_CREATED = 'error.fingerprint_created';
    public const DEDUPLICATED = 'error.deduplicated';
    public const ESCALATED = 'error.escalated';
    public const ALERT_DISPATCHED = 'error.alert_dispatched';
}
