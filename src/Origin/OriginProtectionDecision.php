<?php
namespace Mnb\SecurityCore\Origin;

use Mnb\SecurityCore\Http\Response;

class OriginProtectionDecision
{
    public function __construct(
        private bool $allowed,
        private string $action = 'allow',
        private string $reason = 'allowed',
        private int $status = 200,
        private array $headers = [],
        private ?string $targetHost = null
    ) {}

    public static function allow(string $reason = 'allowed'): self { return new self(true, 'allow', $reason, 200); }
    public static function block(string $reason, int $status = 421): self { return new self(false, 'block', $reason, $status); }
    public static function redirect(string $host, int $status = 301): self { return new self(true, 'redirect', 'redirect_to_canonical_host', $status, ['Location' => 'https://' . $host], $host); }

    public function allowed(): bool { return $this->allowed; }
    public function action(): string { return $this->action; }
    public function reason(): string { return $this->reason; }
    public function status(): int { return $this->status; }
    public function headers(): array { return $this->headers; }
    public function targetHost(): ?string { return $this->targetHost; }

    public function toSafeResponse(): Response
    {
        if ($this->action === 'redirect' && isset($this->headers['Location'])) {
            return Response::text('', $this->status, $this->headers);
        }
        return Response::json([
            'status' => false,
            'message' => match ($this->reason) {
                'untrusted_forwarded_headers' => 'Untrusted forwarded request headers are not allowed.',
                'trusted_proxy_required' => 'Direct origin access is not allowed.',
                'direct_ip_host' => 'Direct server access is not allowed.',
                'unknown_host' => 'Untrusted host.',
                default => 'Origin request is not allowed.',
            },
            'error' => ['code' => strtoupper($this->reason)],
        ], $this->status);
    }

    public function toArray(): array
    {
        return [
            'allowed' => $this->allowed,
            'action' => $this->action,
            'reason' => $this->reason,
            'status' => $this->status,
            'headers' => $this->headers,
            'target_host' => $this->targetHost,
        ];
    }
}
