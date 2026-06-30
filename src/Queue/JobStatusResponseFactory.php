<?php
namespace Mnb\SecurityCore\Queue;

final class JobStatusResponseFactory
{
    public function response(?Job $job): array
    {
        if (!$job) { return ['status'=>false, 'code'=>'JOB_NOT_FOUND']; }
        return ['status'=>true, 'job'=>$job->toArray()];
    }
}
