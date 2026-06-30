<?php
namespace Mnb\SecurityCore\Queue;

final class DeadLetterQueue
{
    public function __construct(private QueueStoreInterface $store, private JobPayloadRedactor $redactor = new JobPayloadRedactor()) {}
    public function move(Job $job, string $reason): void { $this->store->fail($job->withMeta(['redacted_payload'=>$this->redactor->redact($job->payload()->all())]), $reason, true); }
    public function all(): array { return array_map(fn(Job $j) => $j->toArray(), $this->store->deadLetters()); }
    public function count(): int { return count($this->store->deadLetters()); }
}
