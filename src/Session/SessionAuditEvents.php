<?php
namespace Mnb\SecurityCore\Session;

final class SessionAuditEvents
{
    public const CREATED = 'session.created';
    public const VALIDATED = 'session.validated';
    public const ROTATED = 'session.rotated';
    public const REVOKED = 'session.revoked';
    public const EXPIRED_IDLE = 'session.expired_idle';
    public const EXPIRED_ABSOLUTE = 'session.expired_absolute';
    public const CONCURRENT_LIMIT_EXCEEDED = 'session.concurrent_limit_exceeded';
    public const FORCED_LOGOUT = 'session.forced_logout';
    public const DEVICE_REGISTERED = 'session.device_registered';
    public const SUSPICIOUS_CHANGE_DETECTED = 'session.suspicious_change_detected';
    public const REMEMBER_ME_ISSUED = 'remember_me.issued';
    public const REMEMBER_ME_ROTATED = 'remember_me.rotated';
    public const REMEMBER_ME_REVOKED = 'remember_me.revoked';
}
