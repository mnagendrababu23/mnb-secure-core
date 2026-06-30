<?php
namespace Mnb\SecurityCore\Queue;

final class QueuePolicy
{
    public function __construct(private QueueConfig $config) {}
    public static function fromConfig(array $config, string $root = ''): self { return new self(QueueConfig::fromConfig($config, $root)); }
    public function config(): QueueConfig { return $this->config; }

    public function queueConfig(string $queue): array { return $this->config->queue($queue); }
    public function queueExists(string $queue): bool { return isset($this->config->queues()[$queue]); }
    public function shouldForceAsync(string $jobName): bool
    {
        $dispatch = $this->config->dispatch();
        return in_array($jobName, (array)($dispatch['force_async_for'] ?? []), true);
    }

    public function evaluateDispatch(string $jobName, string $queue, array $payload): QueueDecision
    {
        if (!$this->config->enabled()) { return QueueDecision::reject('queue_disabled'); }
        if (!QueueNamePolicy::valid($queue)) { return QueueDecision::reject('invalid_queue_name'); }
        if (!$this->queueExists($queue)) { return QueueDecision::reject('unknown_queue'); }
        $q = $this->queueConfig($queue);
        if (array_key_exists('enabled', $q) && !$q['enabled']) { return QueueDecision::reject('queue_disabled'); }
        $maxPayload = (int)($q['max_payload_bytes'] ?? 65536);
        $bytes = strlen(json_encode($payload, JSON_UNESCAPED_SLASHES) ?: '');
        if ($maxPayload > 0 && $bytes > $maxPayload) { return QueueDecision::reject('payload_too_large', ['payload_bytes'=>$bytes, 'max_payload_bytes'=>$maxPayload]); }
        return QueueDecision::allow($this->shouldForceAsync($jobName) ? 'force_async' : 'queue', 'dispatch_allowed', ['queue'=>$queue]);
    }

    public function maxDepth(string $queue): int { return (int)($this->queueConfig($queue)['max_depth'] ?? 10000); }
    public function defaultPriority(string $queue): string { return (string)($this->queueConfig($queue)['default_priority'] ?? JobPriority::NORMAL); }
    public function visibilityTimeout(string $queue): int { return (int)($this->queueConfig($queue)['visibility_timeout_seconds'] ?? 300); }
    public function toArray(): array { return $this->config->toArray(); }
}
