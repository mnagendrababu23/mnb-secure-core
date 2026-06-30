<?php
namespace Mnb\SecurityCore\Queue;

final class AsyncResponseFactory
{
    public function __construct(private array $dispatchConfig = []) {}
    public static function fromConfig(array $config): self { $q = is_array($config['queue'] ?? null) ? $config['queue'] : []; return new self(is_array($q['dispatch'] ?? null) ? $q['dispatch'] : []); }
    public function accepted(array $dispatchResult, string $baseUrl = '/jobs'): AsyncResponse
    {
        $jobId = (string)($dispatchResult['job_id'] ?? '');
        return new AsyncResponse(true, (int)($this->dispatchConfig['accepted_status_code'] ?? 202), [
            'status'=>true, 'message'=>'Job accepted.', 'job_id'=>$jobId,
            'job_status'=>$dispatchResult['status'] ?? 'queued', 'status_url'=>rtrim($baseUrl, '/') . '/' . $jobId,
        ]);
    }
    public function rejected(array $dispatchResult): AsyncResponse { return new AsyncResponse(false, 422, ['status'=>false, 'message'=>'Job rejected.', 'reason'=>$dispatchResult['reason'] ?? 'unknown']); }
}
