<?php
namespace Mnb\SecurityCore\Session;

final class SessionContext
{
    public function __construct(private string $ip = '', private string $userAgent = '', private array $metadata = []) {}
    public static function fromArray(array $data): self { return new self((string)($data['ip'] ?? ''), (string)($data['user_agent'] ?? ''), is_array($data['metadata'] ?? null) ? $data['metadata'] : []); }
    public function ip(): string { return $this->ip; }
    public function userAgent(): string { return $this->userAgent; }
    public function fingerprint(): string { return SessionFingerprint::create($this->userAgent, $this->ip); }
    public function toArray(): array { return ['ip'=>$this->ip,'user_agent'=>$this->userAgent,'metadata'=>$this->metadata]; }
}
