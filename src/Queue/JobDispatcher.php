<?php
namespace Mnb\SecurityCore\Queue;

final class JobDispatcher
{
    public function __construct(
        private QueuePolicy $policy,
        private QueueStoreInterface $store,
        private JobHandlerRegistry $handlers,
        private JobPayloadProtector $payloadProtector,
        private DuplicateJobGuard $duplicateGuard
    ) {}

    public function dispatch(string $name, array $payload = [], ?string $queue = null, ?string $priority = null, ?string $idempotencyKey = null, ?JobContext $context = null): array
    {
        $queue ??= $this->policy->config()->defaultQueue();
        if (!$this->handlers->has($name)) { return ['accepted'=>false, 'reason'=>'unknown_handler', 'job_name'=>$name]; }
        $duplicate = $this->duplicateGuard->findDuplicate($idempotencyKey);
        if ($duplicate !== null) { return ['accepted'=>true, 'duplicate'=>true, 'job_id'=>$duplicate, 'status'=>'existing']; }
        $inspection = $this->payloadProtector->inspect($payload);
        if (!$inspection['passed']) { return ['accepted'=>false, 'reason'=>'unsafe_payload', 'inspection'=>$inspection]; }
        $decision = $this->policy->evaluateDispatch($name, $queue, $inspection['redacted_payload']);
        if (!$decision->allowed()) { return ['accepted'=>false, 'reason'=>$decision->reason(), 'decision'=>$decision->toArray()]; }
        if ($this->store->metrics()->depthForQueue($queue) >= $this->policy->maxDepth($queue)) { return ['accepted'=>false, 'reason'=>'queue_max_depth_exceeded', 'queue'=>$queue]; }
        $job = Job::create($name, $inspection['redacted_payload'], $queue, $priority ?: $this->policy->defaultPriority($queue), IdempotencyKey::normalize($idempotencyKey), $context);
        $this->store->push($job);
        $this->duplicateGuard->remember($idempotencyKey, $job->id());
        return ['accepted'=>true, 'job_id'=>$job->id(), 'status'=>$job->status(), 'queue'=>$queue, 'async'=>$decision->action() !== 'sync', 'decision'=>$decision->toArray()];
    }
}
