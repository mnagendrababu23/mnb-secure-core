<?php
namespace Mnb\SecurityCore\Cache;

class CacheInvalidator
{
    public function __construct(private TaggedCache $tags) {}

    /** @param list<string> $tags */
    public function invalidateTags(array $tags): int
    {
        return $this->tags->flushTags($tags);
    }

    public function invalidateUserAuthorization(int|string $userId): int
    {
        return $this->invalidateTags(['authz', 'authz:user:' . (string)$userId, 'user:' . (string)$userId]);
    }

    public function invalidateTenant(int|string $tenantId): int
    {
        return $this->invalidateTags(['tenant:' . (string)$tenantId, 'school:' . (string)$tenantId]);
    }

    public function invalidatePolicy(string $policyName): int
    {
        return $this->invalidateTags(['policy:' . $policyName]);
    }
}
