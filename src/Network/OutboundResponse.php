<?php
namespace Mnb\SecurityCore\Network;

final class OutboundResponse
{
    /** @param array<int,string> $headers */
    public function __construct(
        private bool $successful,
        private int $statusCode = 0,
        private string $body = '',
        private array $headers = [],
        private ?string $error = null,
        private bool $blocked = false,
        private bool $truncated = false,
        private array $redirects = []
    ) {}

    public static function deny(string $reason): self
    {
        return new self(false, 0, '', [], $reason, true);
    }

    public static function failed(string $reason): self
    {
        return new self(false, 0, '', [], $reason, false);
    }

    public function successful(): bool { return $this->successful; }
    public function statusCode(): int { return $this->statusCode; }
    public function body(): string { return $this->body; }
    /** @return array<int,string> */ public function headers(): array { return $this->headers; }
    public function error(): ?string { return $this->error; }
    public function blocked(): bool { return $this->blocked; }
    public function truncated(): bool { return $this->truncated; }
    /** @return array<int,string> */ public function redirects(): array { return $this->redirects; }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return [
            'successful' => $this->successful,
            'status_code' => $this->statusCode,
            'body_bytes' => strlen($this->body),
            'error' => $this->error,
            'blocked' => $this->blocked,
            'truncated' => $this->truncated,
            'redirects' => $this->redirects,
        ];
    }
}
