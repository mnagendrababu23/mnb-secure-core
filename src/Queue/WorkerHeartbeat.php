<?php
namespace Mnb\SecurityCore\Queue;

final class WorkerHeartbeat
{
    public function __construct(private string $workerId, private string $queue, private int $time, private int $jobsProcessed = 0) {}
    public static function now(string $workerId, string $queue, int $jobsProcessed = 0): self { return new self($workerId, $queue, time(), $jobsProcessed); }
    public function stale(int $maxAgeSeconds): bool { return (time() - $this->time) > $maxAgeSeconds; }
    public function toArray(): array { return ['worker_id'=>$this->workerId, 'queue'=>$this->queue, 'heartbeat_at'=>date('c', $this->time), 'jobs_processed'=>$this->jobsProcessed, 'stale'=>false]; }
}
