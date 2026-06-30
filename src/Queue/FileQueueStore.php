<?php
namespace Mnb\SecurityCore\Queue;

final class FileQueueStore implements QueueStoreInterface
{
    public function __construct(private string $path, private string $lockPath = '')
    {
        if (!is_dir($this->path)) { @mkdir($this->path, 0775, true); }
        if ($this->lockPath !== '' && !is_dir($this->lockPath)) { @mkdir($this->lockPath, 0775, true); }
    }

    public static function fromConfig(QueueConfig $config): self
    {
        $connection = $config->connection($config->defaultConnection());
        $path = (string)($connection['path'] ?? ($config->root() . '/storage/queue'));
        $lock = (string)($connection['lock_path'] ?? ($config->root() . '/storage/cache/queue-locks'));
        return new self($path, $lock);
    }

    public function push(Job $job): Job { $this->write($job); return $job; }
    public function find(string $jobId): ?Job { $file = $this->file($jobId); return is_file($file) ? Job::fromArray(json_decode((string)file_get_contents($file), true) ?: []) : null; }
    public function reserve(string $queue): ?Job
    {
        $jobs = array_filter($this->allJobs(), fn(Job $j) => $j->queue() === $queue && in_array($j->status(), [JobStatus::QUEUED, JobStatus::RETRYING], true) && $j->availableAt() <= time());
        usort($jobs, fn(Job $a, Job $b) => JobPriority::weight($b->priority()) <=> JobPriority::weight($a->priority()) ?: $a->availableAt() <=> $b->availableAt());
        if (!$jobs) { return null; }
        $reserved = $jobs[0]->withReservedNow();
        $this->write($reserved);
        return $reserved;
    }
    public function save(Job $job): void { $this->write($job); }
    public function acknowledge(string $jobId): void { $job = $this->find($jobId); if ($job) { $this->write($job->withStatus(JobStatus::SUCCEEDED)); } }
    public function fail(Job $job, string $reason, bool $deadLetter = false): void { $this->write($job->withStatus($deadLetter ? JobStatus::DEAD_LETTERED : JobStatus::FAILED)->withMeta(['failure_reason'=>$reason])); }
    public function failed(): array { return array_values(array_filter($this->allJobs(), fn(Job $j) => in_array($j->status(), [JobStatus::FAILED, JobStatus::DEAD_LETTERED], true))); }
    public function deadLetters(): array { return array_values(array_filter($this->allJobs(), fn(Job $j) => $j->status() === JobStatus::DEAD_LETTERED)); }
    public function metrics(): QueueMetrics { return QueueMetrics::fromJobs($this->allJobs()); }

    private function file(string $id): string { return rtrim($this->path, '/\\') . '/' . preg_replace('/[^a-zA-Z0-9._:-]/', '_', $id) . '.json'; }
    private function write(Job $job): void { file_put_contents($this->file($job->id()), json_encode($job->toArray(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)); }
    /** @return array<int,Job> */ private function allJobs(): array
    {
        $jobs = [];
        foreach (glob(rtrim($this->path, '/\\') . '/*.json') ?: [] as $file) {
            $data = json_decode((string)file_get_contents($file), true);
            if (is_array($data)) { $jobs[] = Job::fromArray($data); }
        }
        return $jobs;
    }
}
