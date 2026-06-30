<?php
namespace Mnb\SecurityCore\Authorization;

class AuthorizationAuditEvents
{
    public const ACCESS_ALLOWED = 'access.allowed';
    public const ACCESS_DENIED = 'access.denied';
    public const PERMISSION_DENIED = 'permission.denied';
    public const ROLE_DENIED = 'role.denied';
    public const SCOPE_DENIED = 'scope.denied';
    public const TENANT_DENIED = 'tenant.denied';
    public const FIELD_DENIED = 'field.denied';
    public const POLICY_MISSING = 'policy.missing';
}
