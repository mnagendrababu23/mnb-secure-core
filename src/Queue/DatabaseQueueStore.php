<?php
namespace Mnb\SecurityCore\Queue;

final class DatabaseQueueStore implements QueueStoreInterface
{
    private InMemoryQueueStore $fallback;
    public function __construct() { $this->fallback = new InMemoryQueueStore(); }
    public function push(Job $job): Job { return $this->fallback->push($job); }
    public function find(string $jobId): ?Job { return $this->fallback->find($jobId); }
    public function reserve(string $queue): ?Job { return $this->fallback->reserve($queue); }
    public function save(Job $job): void { $this->fallback->save($job); }
    public function acknowledge(string $jobId): void { $this->fallback->acknowledge($jobId); }
    public function fail(Job $job, string $reason, bool $deadLetter = false): void { $this->fallback->fail($job, $reason, $deadLetter); }
    public function failed(): array { return $this->fallback->failed(); }
    public function deadLetters(): array { return $this->fallback->deadLetters(); }
    public function metrics(): QueueMetrics { return $this->fallback->metrics(); }
}
