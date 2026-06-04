<?php
namespace Mnb\SecurityCore\Authz\Policies;

use Mnb\SecurityCore\Authz\TenantContext;
use Mnb\SecurityCore\Contracts\PolicyInterface;

class DatabaseResourcePolicy implements PolicyInterface
{
    public function __construct(private string $resourcePrefix) {}

    public function allows(TenantContext $context, string $ability, mixed $resource = null): bool
    {
        if (in_array('super_admin', $context->roles, true)) {
            return true;
        }

        $permission = $this->resourcePrefix . '.' . $ability;
        if (!in_array($permission, $context->permissions, true)) {
            return false;
        }

        if (is_array($resource)) {
            if (isset($resource['school_id']) && $context->schoolId !== null && (string)$resource['school_id'] !== (string)$context->schoolId) {
                return false;
            }
            if (isset($resource['branch_id']) && $context->branchId !== null && (string)$resource['branch_id'] !== (string)$context->branchId) {
                return false;
            }
            if (isset($resource['academic_year_id']) && $context->academicYearId !== null && (string)$resource['academic_year_id'] !== (string)$context->academicYearId) {
                return false;
            }
        }

        return true;
    }
}
