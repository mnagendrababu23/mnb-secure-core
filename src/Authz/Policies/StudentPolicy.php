<?php
namespace Mnb\SecurityCore\Authz\Policies;

use Mnb\SecurityCore\Authz\TenantContext;
use Mnb\SecurityCore\Authz\TenantGuard;
use Mnb\SecurityCore\Contracts\PolicyInterface;

class StudentPolicy implements PolicyInterface
{
    public function __construct(private TenantGuard $tenantGuard = new TenantGuard()) {}

    public function allows(TenantContext $context, string $ability, mixed $resource = null): bool
    {
        $permission = 'student.' . $ability;
        if (!in_array('*', $context->permissions, true) && !in_array($permission, $context->permissions, true)) {
            return false;
        }
        if (is_array($resource)) {
            return $this->tenantGuard->recordBelongsToContext($resource, $context)
                && $this->tenantGuard->classSectionAllowed($resource, $context);
        }
        return true;
    }
}
