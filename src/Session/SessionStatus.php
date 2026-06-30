<?php
namespace Mnb\SecurityCore\Session;

final class SessionStatus
{
    public const ACTIVE = 'active';
    public const IDLE_EXPIRED = 'idle_expired';
    public const ABSOLUTE_EXPIRED = 'absolute_expired';
    public const REVOKED = 'revoked';
    public const FORCED_LOGOUT = 'forced_logout';
    public const SUSPICIOUS = 'suspicious';
    public const ROTATED = 'rotated';
}
