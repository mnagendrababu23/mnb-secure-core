<?php
namespace Mnb\SecurityCore\Incident;

use Mnb\SecurityCore\Cache\CacheInvalidator;
use Mnb\SecurityCore\Logging\SecurityAuditEvent;
use Mnb\SecurityCore\Logging\SecurityAuditTrail;

class ContainmentActionRunner
{
    public function __construct(private ?CacheInvalidator $cacheInvalidator = null, private ?SecurityAuditTrail $audit = null) {}
    /** @param list<string> $actions @return list<array<string,mixed>> */
    public function run(array $actions, array $context = []): array
    {
        $results = [];
        foreach ($actions as $action) { $results[] = $this->runOne((string)$action, $context); }
        return $results;
    }
    /** @return array<string,mixed> */
    private function runOne(string $action, array $context): array
    {
        $status = 'recommended'; $detail = 'Action recorded for operator review.';
        if ($action === 'invalidate_cache') { $count = $this->cacheInvalidator?->invalidateTags((array)($context['cache_tags'] ?? ['incident'])) ?? 0; $status='executed'; $detail='Invalidated tagged cache entries: ' . $count; }
        if ($action === 'invalidate_user_auth_cache' && isset($context['user_id'])) { $count = $this->cacheInvalidator?->invalidateUserAuthorization($context['user_id']) ?? 0; $status='executed'; $detail='Invalidated user authorization cache entries: ' . $count; }
        if ($action === 'invalidate_tenant_cache' && isset($context['tenant_id'])) { $count = $this->cacheInvalidator?->invalidateTenant($context['tenant_id']) ?? 0; $status='executed'; $detail='Invalidated tenant cache entries: ' . $count; }
        $result = ['action'=>$action,'status'=>$status,'detail'=>$detail];
        $this->audit?->record(SecurityAuditEvent::make('incident', 'containment.' . preg_replace('/[^a-z0-9_.:-]+/i', '_', $action), SecurityAuditEvent::OUTCOME_INFO, SecurityAuditEvent::SEVERITY_NOTICE, [], [], [], $result));
        return $result;
    }
}
