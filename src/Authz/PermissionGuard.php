<?php
namespace Mnb\SecurityCore\Authz;

class PermissionGuard
{
    public function can(TenantContext $context, string $permission): bool
    {
        return in_array('*', $context->permissions, true) || in_array($permission, $context->permissions, true);
    }

    public function hasRole(TenantContext $context, string $role): bool
    {
        return in_array($role, $context->roles, true);
    }
}
