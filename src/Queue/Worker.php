<?php
namespace Mnb\SecurityCore\Queue;

final class Worker
{
    public function __construct(private QueueStoreInterface $store, private JobHandlerRegistry $handlers, private RetryPolicy $retryPolicy, private DeadLetterQueue $deadLetterQueue, private WorkerConfig $config) {}

    public function workOnce(string $queue): array
    {
        $job = $this->store->reserve($queue);
        if (!$job) { return ['processed'=>false, 'reason'=>'no_job_available', 'queue'=>$queue]; }
        $handler = $this->handlers->get($job->name());
        if (!$handler) {
            $this->deadLetterQueue->move($job, 'unknown_handler');
            return ['processed'=>true, 'job_id'=>$job->id(), 'status'=>JobStatus::DEAD_LETTERED, 'reason'=>'unknown_handler'];
        }
        $job = $job->withAttemptIncrement()->withStatus(JobStatus::RUNNING);
        $this->store->save($job);
        try { $result = $handler->handle($job); } catch (\Throwable $e) { $result = JobResult::failure($e->getMessage(), ['exception'=>get_class($e)], true); }
        if ($result->passed()) {
            $this->store->acknowledge($job->id());
            return ['processed'=>true, 'job_id'=>$job->id(), 'status'=>JobStatus::SUCCEEDED, 'result'=>$result->toArray()];
        }
        $retry = $this->retryPolicy->decide($job, $result);
        if ($retry->retry()) {
            $this->store->save($job->withStatus(JobStatus::RETRYING)->withAvailableAt(time() + $retry->delaySeconds())->withMeta(['last_error'=>$result->error(), 'retry'=>$retry->toArray()]));
            return ['processed'=>true, 'job_id'=>$job->id(), 'status'=>JobStatus::RETRYING, 'retry'=>$retry->toArray()];
        }
        $this->deadLetterQueue->move($job, $result->error() ?: $retry->toArray()['reason']);
        return ['processed'=>true, 'job_id'=>$job->id(), 'status'=>JobStatus::DEAD_LETTERED, 'retry'=>$retry->toArray()];
    }
}
