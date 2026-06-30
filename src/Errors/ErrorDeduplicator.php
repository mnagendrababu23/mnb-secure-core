<?php
namespace Mnb\SecurityCore\Errors;

final class ErrorDeduplicator
{
    /** @var array<string,array{count:int,last_seen:int}> */
    private array $occurrences = [];

    public function record(string $fingerprint, ?int $now = null): int
    {
        $now ??= time();
        if (!isset($this->occurrences[$fingerprint])) {
            $this->occurrences[$fingerprint] = ['count' => 0, 'last_seen' => $now];
        }
        $this->occurrences[$fingerprint]['count']++;
        $this->occurrences[$fingerprint]['last_seen'] = $now;
        return $this->occurrences[$fingerprint]['count'];
    }

    public function count(string $fingerprint): int
    {
        return $this->occurrences[$fingerprint]['count'] ?? 0;
    }

    /** @return array<string,array<string,int>> */
    public function all(): array
    {
        return $this->occurrences;
    }
}
