<?php
namespace Mnb\SecurityCore\Queue;

final class QueueMetrics
{
    public function __construct(private array $depthByQueue = [], private int $failed = 0, private int $deadLetters = 0, private int $total = 0) {}
    public static function fromJobs(array $jobs): self
    {
        $depth = []; $failed = 0; $dead = 0;
        foreach ($jobs as $job) {
            if (!$job instanceof Job) { continue; }
            if (in_array($job->status(), [JobStatus::QUEUED, JobStatus::RETRYING, JobStatus::RESERVED, JobStatus::RUNNING], true)) { $depth[$job->queue()] = ($depth[$job->queue()] ?? 0) + 1; }
            if ($job->status() === JobStatus::FAILED) { $failed++; }
            if ($job->status() === JobStatus::DEAD_LETTERED) { $dead++; }
        }
        return new self($depth, $failed, $dead, count($jobs));
    }
    public function depthForQueue(string $queue): int { return (int)($this->depthByQueue[$queue] ?? 0); }
    public function failedCount(): int { return $this->failed; }
    public function deadLetterCount(): int { return $this->deadLetters; }
    public function toArray(): array { return ['total_jobs'=>$this->total, 'depth_by_queue'=>$this->depthByQueue, 'failed'=>$this->failed, 'dead_letters'=>$this->deadLetters]; }
}
