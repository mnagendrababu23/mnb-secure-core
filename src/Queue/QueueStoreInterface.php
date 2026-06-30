<?php
namespace Mnb\SecurityCore\Queue;

interface QueueStoreInterface
{
    public function push(Job $job): Job;
    public function find(string $jobId): ?Job;
    public function reserve(string $queue): ?Job;
    public function save(Job $job): void;
    public function acknowledge(string $jobId): void;
    public function fail(Job $job, string $reason, bool $deadLetter = false): void;
    /** @return array<int,Job> */ public function failed(): array;
    /** @return array<int,Job> */ public function deadLetters(): array;
    public function metrics(): QueueMetrics;
}
