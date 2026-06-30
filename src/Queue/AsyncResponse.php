<?php
namespace Mnb\SecurityCore\Queue;

final class AsyncResponse
{
    public function __construct(private bool $accepted, private int $statusCode, private array $body) {}
    public function accepted(): bool { return $this->accepted; }
    public function statusCode(): int { return $this->statusCode; }
    public function body(): array { return $this->body; }
    public function toArray(): array { return ['accepted'=>$this->accepted, 'status_code'=>$this->statusCode, 'body'=>$this->body]; }
}
