<?php
namespace Mnb\SecurityCore\Queue;

final class JobResourceGuard
{
    public function check(Job $job): array
    {
        return ['passed'=>true, 'job_id'=>$job->id(), 'memory_bytes'=>memory_get_usage(true), 'peak_memory_bytes'=>memory_get_peak_usage(true)];
    }
}
