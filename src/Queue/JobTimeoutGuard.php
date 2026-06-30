<?php
namespace Mnb\SecurityCore\Queue;

final class JobTimeoutGuard
{
    public function __construct(private int $timeoutSeconds = 300) {}
    public function check(float $startedAt): array
    {
        $elapsed = microtime(true) - $startedAt;
        return ['passed'=>$elapsed <= $this->timeoutSeconds, 'elapsed_seconds'=>$elapsed, 'timeout_seconds'=>$this->timeoutSeconds];
    }
}
