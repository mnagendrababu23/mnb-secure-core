<?php
namespace Mnb\SecurityCore\Memory;

class WorkerMemorySupervisor
{
    public function __construct(private OperationMemoryProfile $profile, private MemoryLeakDetector $detector) {}
    public function check(int $jobsProcessed, int $startBytes, ?int $endBytes = null): array
    {
        $growthThreshold = $this->profile->restartAfterGrowthMb() * 1048576;
        $leak = $this->detector->analyze($startBytes, $endBytes, $growthThreshold);
        $jobLimit = $jobsProcessed >= $this->profile->restartAfterJobs();
        return [
            'passed' => !$leak['restart_recommended'] && !$jobLimit,
            'restart_recommended' => $leak['restart_recommended'] || $jobLimit,
            'reason' => $leak['restart_recommended'] ? 'memory_growth_threshold_exceeded' : ($jobLimit ? 'job_count_threshold_reached' : 'within_worker_budget'),
            'jobs_processed' => $jobsProcessed,
            'profile' => $this->profile->toArray(),
            'leak' => $leak,
        ];
    }
}
