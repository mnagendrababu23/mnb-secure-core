<?php
namespace Mnb\SecurityCore\Authz;

use Mnb\SecurityCore\Contracts\PolicyInterface;

class PolicyRegistry
{
    /** @var array<string,PolicyInterface> */
    private array $policies = [];

    public function register(string $resourceType, PolicyInterface $policy): void
    {
        $this->policies[$resourceType] = $policy;
    }

    public function allows(TenantContext $context, string $resourceType, string $ability, mixed $resource = null): bool
    {
        if (!isset($this->policies[$resourceType])) {
            return false;
        }
        return $this->policies[$resourceType]->allows($context, $ability, $resource);
    }
}
