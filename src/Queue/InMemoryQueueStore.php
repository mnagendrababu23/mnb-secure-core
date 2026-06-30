<?php
namespace Mnb\SecurityCore\Queue;

final class InMemoryQueueStore implements QueueStoreInterface
{
    /** @var array<string,Job> */ private array $jobs = [];
    public function push(Job $job): Job { $this->jobs[$job->id()] = $job; return $job; }
    public function find(string $jobId): ?Job { return $this->jobs[$jobId] ?? null; }
    public function reserve(string $queue): ?Job
    {
        $candidates = array_filter($this->jobs, fn(Job $j) => $j->queue() === $queue && in_array($j->status(), [JobStatus::QUEUED, JobStatus::RETRYING], true) && $j->availableAt() <= time());
        usort($candidates, fn(Job $a, Job $b) => JobPriority::weight($b->priority()) <=> JobPriority::weight($a->priority()) ?: $a->availableAt() <=> $b->availableAt());
        if (!$candidates) { return null; }
        $reserved = $candidates[0]->withReservedNow();
        $this->jobs[$reserved->id()] = $reserved;
        return $reserved;
    }
    public function save(Job $job): void { $this->jobs[$job->id()] = $job; }
    public function acknowledge(string $jobId): void { if (isset($this->jobs[$jobId])) { $this->jobs[$jobId] = $this->jobs[$jobId]->withStatus(JobStatus::SUCCEEDED); } }
    public function fail(Job $job, string $reason, bool $deadLetter = false): void { $this->jobs[$job->id()] = $job->withStatus($deadLetter ? JobStatus::DEAD_LETTERED : JobStatus::FAILED)->withMeta(['failure_reason'=>$reason]); }
    public function failed(): array { return array_values(array_filter($this->jobs, fn(Job $j) => in_array($j->status(), [JobStatus::FAILED, JobStatus::DEAD_LETTERED], true))); }
    public function deadLetters(): array { return array_values(array_filter($this->jobs, fn(Job $j) => $j->status() === JobStatus::DEAD_LETTERED)); }
    public function metrics(): QueueMetrics { return QueueMetrics::fromJobs(array_values($this->jobs)); }
}
