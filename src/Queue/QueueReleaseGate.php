<?php
namespace Mnb\SecurityCore\Queue;

final class QueueReleaseGate
{
    public function __construct(private array $policy = []) {}
    public static function fromConfig(array $config): self { $q = is_array($config['queue'] ?? null) ? $config['queue'] : []; return new self(is_array($q['release_gate'] ?? null) ? $q['release_gate'] : []); }
    public function evaluate(QueueMetrics $metrics, JobHandlerRegistry $registry, array $requiredHandlers = []): array
    {
        $blockers = [];
        if (!empty($this->policy['block_on_dead_letter_growth']) && $metrics->deadLetterCount() > 0) { $blockers[] = ['reason'=>'dead_letter_growth', 'count'=>$metrics->deadLetterCount()]; }
        if (!empty($this->policy['block_on_failed_jobs']) && $metrics->failedCount() > 0) { $blockers[] = ['reason'=>'failed_jobs', 'count'=>$metrics->failedCount()]; }
        if (!empty($this->policy['block_on_missing_handlers'])) { foreach ($requiredHandlers as $handler) { if (!$registry->has((string)$handler)) { $blockers[] = ['reason'=>'missing_handler', 'handler'=>$handler]; } } }
        return ['passed'=>empty($blockers), 'blockers'=>$blockers, 'metrics'=>$metrics->toArray(), 'handlers'=>$registry->toArray()];
    }
}
