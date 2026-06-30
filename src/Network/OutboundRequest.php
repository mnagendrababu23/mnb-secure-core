<?php
namespace Mnb\SecurityCore\Network;

final class OutboundRequest
{
    /** @param array<string,string> $headers */
    public function __construct(
        private string $method,
        private string $url,
        private array $headers = [],
        private ?string $body = null
    ) {}

    public function method(): string { return strtoupper($this->method); }
    public function url(): string { return $this->url; }
    /** @return array<string,string> */ public function headers(): array { return $this->headers; }
    public function body(): ?string { return $this->body; }
}
