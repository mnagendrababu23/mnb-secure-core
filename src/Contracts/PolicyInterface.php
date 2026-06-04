<?php
namespace Mnb\SecurityCore\Contracts;

use Mnb\SecurityCore\Authz\TenantContext;

interface PolicyInterface
{
    public function allows(TenantContext $context, string $ability, mixed $resource = null): bool;
}
