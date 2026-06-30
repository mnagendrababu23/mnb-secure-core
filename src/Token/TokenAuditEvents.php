<?php
namespace Mnb\SecurityCore\Token;

final class TokenAuditEvents
{
    public const ISSUED = 'token.issued';
    public const VALIDATED = 'token.validated';
    public const REVOKED = 'token.revoked';
    public const REVOCATION_CHECKED = 'token.revocation_checked';
    public const REFRESH_ROTATED = 'token.refresh_rotated';
    public const REFRESH_REUSE_DETECTED = 'token.refresh_reuse_detected';
    public const FAMILY_REVOKED = 'token.family_revoked';
    public const INTROSPECTION_CHECKED = 'token.introspection_checked';
}
