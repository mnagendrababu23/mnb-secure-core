<?php
namespace Mnb\SecurityCore\Runtime;

final class RuntimeAuditEvents
{
    public const PROCESS_ALLOWED = 'runtime.process.allowed';
    public const PROCESS_BLOCKED = 'runtime.process.blocked';
    public const PROCESS_FAILED = 'runtime.process.failed';
    public const PROCESS_TIMEOUT = 'runtime.process.timeout';
    public const PROCESS_OUTPUT_LIMIT = 'runtime.process.output_limit';
}
