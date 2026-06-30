<?php
namespace Mnb\SecurityCore\Queue;

final class JobResult
{
    public function __construct(private bool $passed, private array $data = [], private ?string $error = null, private bool $retryable = true) {}
    public static function success(array $data = []): self { return new self(true, $data); }
    public static function failure(string $error, array $data = [], bool $retryable = true): self { return new self(false, $data, $error, $retryable); }
    public function passed(): bool { return $this->passed; }
    public function retryable(): bool { return $this->retryable; }
    public function error(): ?string { return $this->error; }
    public function data(): array { return $this->data; }
    public function toArray(): array { return ['passed'=>$this->passed, 'error'=>$this->error, 'retryable'=>$this->retryable, 'data'=>$this->data]; }
}
