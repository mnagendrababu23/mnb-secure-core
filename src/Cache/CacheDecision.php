<?php
namespace Mnb\SecurityCore\Cache;

class CacheDecision
{
    /** @param array<string,mixed> $meta */
    public function __construct(
        private bool $allowed,
        private string $policy,
        private string $key,
        private string $reason = 'allowed',
        private bool $encrypted = false,
        private string $dataClass = CachePolicy::INTERNAL,
        private array $meta = []
    ) {}

    public static function allow(CachePolicy $policy, string $key, bool $encrypted, array $meta = []): self
    {
        return new self(true, $policy->name(), $key, 'allowed', $encrypted, $policy->dataClass(), $meta);
    }

    public static function deny(CachePolicy $policy, string $reason, array $meta = []): self
    {
        return new self(false, $policy->name(), '', $reason, false, $policy->dataClass(), $meta);
    }

    public function allowed(): bool { return $this->allowed; }
    public function denied(): bool { return !$this->allowed; }
    public function policy(): string { return $this->policy; }
    public function key(): string { return $this->key; }
    public function reason(): string { return $this->reason; }
    public function encrypted(): bool { return $this->encrypted; }
    public function dataClass(): string { return $this->dataClass; }
    /** @return array<string,mixed> */ public function meta(): array { return $this->meta; }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return [
            'allowed' => $this->allowed,
            'policy' => $this->policy,
            'key' => $this->key,
            'reason' => $this->reason,
            'encrypted' => $this->encrypted,
            'data_class' => $this->dataClass,
            'meta' => $this->meta,
        ];
    }
}
