<?php
namespace Mnb\SecurityCore\Throughput;

class ConcurrencyToken
{
    private bool $released = false;

    public function __construct(private ConcurrencyStore $store, private string $profile, private string $id, private int $limit) {}

    public function id(): string { return $this->id; }
    public function profile(): string { return $this->profile; }
    public function limit(): int { return $this->limit; }

    public function release(): void
    {
        if (!$this->released) {
            $this->store->release($this->profile, $this->id);
            $this->released = true;
        }
    }

    public function __destruct()
    {
        $this->release();
    }

    public function toArray(): array
    {
        return ['id' => $this->id, 'profile' => $this->profile, 'limit' => $this->limit, 'released' => $this->released];
    }
}
