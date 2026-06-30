<?php
namespace Mnb\SecurityCore\Queue;

final class QueueAuditEvents
{
    public const JOB_DISPATCHED = 'queue.job.dispatched';
    public const JOB_REJECTED = 'queue.job.rejected';
    public const JOB_DUPLICATE_DETECTED = 'queue.job.duplicate_detected';
    public const JOB_RESERVED = 'queue.job.reserved';
    public const JOB_STARTED = 'queue.job.started';
    public const JOB_SUCCEEDED = 'queue.job.succeeded';
    public const JOB_FAILED = 'queue.job.failed';
    public const JOB_RETRY_SCHEDULED = 'queue.job.retry_scheduled';
    public const JOB_DEAD_LETTERED = 'queue.job.dead_lettered';
    public const JOB_CANCELLED = 'queue.job.cancelled';
    public const WORKER_STARTED = 'queue.worker.started';
    public const WORKER_HEARTBEAT = 'queue.worker.heartbeat';
    public const WORKER_STOPPED = 'queue.worker.stopped';
    public const WORKER_MEMORY_RESTART_RECOMMENDED = 'queue.worker.memory_restart_recommended';
    public const PAYLOAD_REDACTED = 'queue.payload.redacted';
    public const PAYLOAD_BLOCKED = 'queue.payload.blocked';
    public const RELEASE_GATE_BLOCKED = 'queue.release_gate.blocked';
    public const RELEASE_GATE_PASSED = 'queue.release_gate.passed';
}
