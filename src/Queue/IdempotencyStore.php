<?php
namespace Mnb\SecurityCore\Queue;

final class IdempotencyStore
{
    /** @var array<string,array{job_id:string,expires:int}> */ private array $map = [];
    public function __construct(private int $ttlSeconds = 86400) {}
    public function get(string $key): ?string { $this->cleanup(); return $this->map[$key]['job_id'] ?? null; }
    public function put(string $key, string $jobId): void { $this->map[$key] = ['job_id'=>$jobId, 'expires'=>time()+$this->ttlSeconds]; }
    public function cleanup(): void { $now = time(); foreach ($this->map as $k=>$v) { if ($v['expires'] < $now) { unset($this->map[$k]); } } }
}
