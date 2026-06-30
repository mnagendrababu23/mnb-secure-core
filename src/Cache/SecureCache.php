<?php
namespace Mnb\SecurityCore\Cache;

use Mnb\SecurityCore\Contracts\CacheInterface;
use Mnb\SecurityCore\Data\KeyRing;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Logging\SecurityAuditEvent;
use Mnb\SecurityCore\Logging\SecurityAuditTrail;

class SecureCache
{
    public function __construct(
        private CacheInterface $cache,
        private CacheRegistry $registry,
        private CacheKeyBuilder $keys,
        private SafeCacheSerializer $serializer,
        private ?KeyRing $keyRing = null,
        private ?SecurityAuditTrail $audit = null,
        private array $security = [],
        private ?TaggedCache $tagged = null,
    ) {
        $this->tagged ??= new TaggedCache($cache);
    }

    /** @param array<string,mixed> $context */
    public function decision(string $policyName, array $context = [], ?Request $request = null): CacheDecision
    {
        $policy = $this->registry->get($policyName);
        if (!$policy->cacheEnabled()) {
            return CacheDecision::deny($policy, 'cache_disabled');
        }
        if (!empty($this->security['deny_highly_sensitive']) && $policy->dataClass() === CachePolicy::HIGHLY_SENSITIVE) {
            return CacheDecision::deny($policy, 'highly_sensitive_cache_denied');
        }
        $context = $this->keys->contextFromRequest($context, $request);
        if ($policy->tenantScoped() && empty($context['tenant_id']) && empty($context['school_id'])) {
            return CacheDecision::deny($policy, 'tenant_scope_missing');
        }
        if ($policy->userScoped() && empty($context['user_id'])) {
            return CacheDecision::deny($policy, 'user_scope_missing');
        }
        $encrypted = $policy->shouldEncrypt((bool)($this->security['encrypt_sensitive'] ?? true));
        if ($encrypted && !$this->keyRing) {
            return CacheDecision::deny($policy, 'encryption_keyring_missing');
        }
        return CacheDecision::allow($policy, $this->keys->build($policy, $context, $request), $encrypted, ['context' => $this->safeContext($context)]);
    }

    /** @param array<string,mixed> $context */
    public function get(string $policyName, array $context = [], mixed $default = null, ?Request $request = null): mixed
    {
        $decision = $this->decision($policyName, $context, $request);
        if ($decision->denied()) {
            $this->auditDecision('denied', $decision);
            return $default;
        }
        $stored = $this->cache->get($decision->key(), null);
        if (!is_string($stored)) {
            return $default;
        }
        try {
            if ($decision->encrypted()) {
                $stored = $this->keyRing?->decrypt($stored, $this->aad($decision->policy())) ?? '';
            }
            $value = $this->serializer->decode($stored);
            $this->auditDecision('hit', $decision);
            return $value;
        } catch (\Throwable) {
            $this->cache->forget($decision->key());
            return $default;
        }
    }

    /** @param array<string,mixed> $context */
    public function put(string $policyName, array $context, mixed $value, ?Request $request = null): CacheDecision
    {
        $decision = $this->decision($policyName, $context, $request);
        if ($decision->denied()) {
            $this->auditDecision('denied', $decision);
            return $decision;
        }
        $policy = $this->registry->get($policyName);
        $payload = $this->serializer->encode($value, $policy->maxValueBytes());
        if ($decision->encrypted()) {
            $payload = $this->keyRing?->encrypt($payload, $this->aad($policyName)) ?? $payload;
        }
        $tags = $this->tagsFor($policy, $context);
        $this->tagged?->put($decision->key(), $payload, $this->ttlWithJitter($policy->ttlSeconds()), $tags);
        $this->auditDecision('write', $decision, ['tags' => $tags]);
        return $decision;
    }

    /** @template T @param array<string,mixed> $context @param callable():T $callback @return T */
    public function remember(string $policyName, array $context, callable $callback, ?Request $request = null): mixed
    {
        $existing = $this->get($policyName, $context, null, $request);
        if ($existing !== null) {
            return $existing;
        }
        $value = $callback();
        $this->put($policyName, $context, $value, $request);
        return $value;
    }

    /** @param array<string,mixed> $context */
    public function forget(string $policyName, array $context = [], ?Request $request = null): void
    {
        $decision = $this->decision($policyName, $context, $request);
        if ($decision->allowed()) {
            $this->cache->forget($decision->key());
            $this->auditDecision('forget', $decision);
        }
    }

    /** @param list<string> $tags */
    public function invalidateTags(array $tags): int
    {
        return $this->tagged?->flushTags($tags) ?? 0;
    }

    /** @param array<string,mixed> $context @return list<string> */
    private function tagsFor(CachePolicy $policy, array $context): array
    {
        $tags = $policy->tags();
        $tags[] = 'policy:' . $policy->name();
        $tags[] = 'class:' . $policy->dataClass();
        foreach (['tenant_id' => 'tenant', 'school_id' => 'school', 'user_id' => 'user'] as $key => $prefix) {
            if (!empty($context[$key])) {
                $tags[] = $prefix . ':' . (string)$context[$key];
            }
        }
        return array_values(array_unique($tags));
    }

    private function ttlWithJitter(int $ttl): int
    {
        $percent = (int)($this->security['jitter_percent'] ?? 0);
        if ($ttl < 2 || $percent < 1) {
            return max(1, $ttl);
        }
        $delta = max(1, (int)floor($ttl * min(50, $percent) / 100));
        return max(1, $ttl + random_int(-$delta, $delta));
    }

    private function aad(string $policy): string
    {
        return 'secure-cache:' . $policy;
    }

    private function auditDecision(string $action, CacheDecision $decision, array $meta = []): void
    {
        if (!$this->audit) {
            return;
        }
        try {
            $this->audit->record(SecurityAuditEvent::make(
                SecurityAuditEvent::CATEGORY_SYSTEM,
                'cache.' . $action,
                $action === 'denied' ? SecurityAuditEvent::OUTCOME_DENIED : SecurityAuditEvent::OUTCOME_INFO,
                $action === 'denied' ? SecurityAuditEvent::SEVERITY_WARNING : SecurityAuditEvent::SEVERITY_INFO,
                [],
                ['policy' => $decision->policy(), 'key_fingerprint' => $decision->key() !== '' ? SecurityAuditEvent::fingerprint($decision->key()) : null],
                [],
                ['reason' => $decision->reason(), 'encrypted' => $decision->encrypted(), 'data_class' => $decision->dataClass()] + $meta
            ));
        } catch (\Throwable) {
            // Cache audit must never break application caching.
        }
    }

    /** @param array<string,mixed> $context @return array<string,mixed> */
    private function safeContext(array $context): array
    {
        return array_intersect_key($context, array_flip(['tenant_id', 'school_id', 'branch_id', 'academic_year_id', 'user_id', 'resource_id', 'route', 'route_name']));
    }
}
