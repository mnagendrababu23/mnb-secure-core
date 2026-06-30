<?php
namespace Mnb\SecurityCore\Queue;

final class WorkerSupervisor
{
    public function __construct(private WorkerConfig $config) {}
    public function check(int $jobsProcessed, int $runtimeSeconds, array $memoryReport = []): WorkerHealthReport
    {
        $checks = [
            'job_limit_ok' => $jobsProcessed < $this->config->maxJobs(),
            'runtime_ok' => $runtimeSeconds < $this->config->maxRuntimeSeconds(),
            'memory_ok' => !($memoryReport['restart_recommended'] ?? false),
        ];
        return new WorkerHealthReport(!in_array(false, $checks, true), $checks);
    }
}
