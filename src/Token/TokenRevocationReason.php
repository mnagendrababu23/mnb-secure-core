<?php
namespace Mnb\SecurityCore\Token;

final class TokenRevocationReason
{
    public const LOGOUT = 'logout';
    public const ADMIN_REVOKE = 'admin_revoke';
    public const PASSWORD_CHANGED = 'password_changed';
    public const ROLE_CHANGED = 'role_changed';
    public const PERMISSION_CHANGED = 'permission_changed';
    public const ACCOUNT_DISABLED = 'account_disabled';
    public const REFRESH_REUSE_DETECTED = 'refresh_reuse_detected';
    public const SECURITY_INCIDENT = 'security_incident';
    public const EXPIRED = 'expired';
    public const COMPROMISED = 'compromised';

    public static function safe(string $reason): string
    {
        $reason = strtolower(trim($reason));
        return preg_match('/^[a-z0-9_:-]{1,80}$/', $reason) ? $reason : self::ADMIN_REVOKE;
    }
}
