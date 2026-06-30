<?php
namespace Mnb\SecurityCore\Queue;

final class RetryPolicy
{
    private BackoffStrategy $backoff;
    public function __construct(private array $config = []) { $this->backoff = BackoffStrategy::fromArray($config); }
    public static function fromConfig(array $config): self { $queue = is_array($config['queue'] ?? null) ? $config['queue'] : []; return new self(is_array($queue['retry'] ?? null) ? $queue['retry'] : []); }
    public function decide(Job $job, JobResult $result): RetryDecision
    {
        if (array_key_exists('enabled', $this->config) && !$this->config['enabled']) { return new RetryDecision(false, 'retry_disabled'); }
        if (!$result->retryable()) { return new RetryDecision(false, 'non_retryable_error'); }
        $error = strtolower((string)$result->error());
        foreach (['authorization', 'validation', 'unknown_handler', 'payload', 'blocked'] as $nonRetryable) {
            if (str_contains($error, $nonRetryable)) { return new RetryDecision(false, 'non_retryable_' . $nonRetryable); }
        }
        $max = (int)($this->config['max_attempts'] ?? 3);
        if ($job->attempts() >= $max) { return new RetryDecision(false, 'max_attempts_reached'); }
        return new RetryDecision(true, 'retry_scheduled', $this->backoff->delay($job->attempts() + 1));
    }
    public function toArray(): array { return ['enabled'=>(bool)($this->config['enabled'] ?? true), 'max_attempts'=>(int)($this->config['max_attempts'] ?? 3), 'backoff'=>$this->config['backoff'] ?? 'exponential']; }
}
