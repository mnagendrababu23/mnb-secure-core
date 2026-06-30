<?php
namespace Mnb\SecurityCore\Memory;

final class MemoryAuditEvents
{
    public const BUDGET_ALLOWED = 'memory.budget.allowed';
    public const BUDGET_BLOCKED = 'memory.budget.blocked';
    public const STREAM_READ_BLOCKED = 'memory.stream.read_blocked';
    public const STREAM_WRITE_BLOCKED = 'memory.stream.write_blocked';
    public const PAYLOAD_BLOCKED = 'memory.payload.blocked';
    public const OUTPUT_BUFFER_BLOCKED = 'memory.output_buffer.blocked';
    public const RESOURCE_SCOPE_CLEANED = 'memory.resource_scope.cleaned';
    public const TEMP_CLEANUP_PLANNED = 'memory.temp.cleanup_planned';
    public const WORKER_RESTART_RECOMMENDED = 'memory.worker.restart_recommended';
}
