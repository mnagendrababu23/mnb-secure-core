<?php
namespace Mnb\SecurityCore\Authorization;

class AuthorizationDecision
{
    /** @param array<string,mixed> $context */
    public function __construct(
        private bool $allowed,
        private string $policyName,
        private string $action,
        private ?string $resourceName = null,
        private string $reason = 'allowed',
        private int $statusCode = 403,
        private bool $auditRequired = false,
        private array $context = [],
        private ?string $code = null
    ) {}

    /** @param array<string,mixed> $context */
    public static function allow(string $policyName, string $action, ?string $resourceName = null, bool $auditRequired = false, array $context = []): self
    {
        return new self(true, $policyName, $action, $resourceName, 'allowed', 200, $auditRequired, $context, 'authorized');
    }

    /** @param array<string,mixed> $context */
    public static function deny(string $policyName, string $action, ?string $resourceName, string $reason, string $code = 'authorization_denied', bool $auditRequired = true, array $context = [], int $statusCode = 403): self
    {
        return new self(false, $policyName, $action, $resourceName, $reason, $statusCode, $auditRequired, $context, $code);
    }

    public function allowed(): bool { return $this->allowed; }
    public function denied(): bool { return !$this->allowed; }
    public function policyName(): string { return $this->policyName; }
    public function action(): string { return $this->action; }
    public function resourceName(): ?string { return $this->resourceName; }
    public function reason(): string { return $this->reason; }
    public function statusCode(): int { return $this->statusCode; }
    public function auditRequired(): bool { return $this->auditRequired; }
    public function code(): string { return $this->code ?: ($this->allowed ? 'authorized' : 'authorization_denied'); }
    public function safeMessage(): string { return $this->allowed ? 'Allowed' : 'Access denied'; }
    /** @return array<string,mixed> */ public function context(): array { return $this->context; }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return [
            'allowed' => $this->allowed,
            'policy' => $this->policyName,
            'action' => $this->action,
            'resource' => $this->resourceName,
            'reason' => $this->reason,
            'code' => $this->code(),
            'status_code' => $this->statusCode,
            'audit_required' => $this->auditRequired,
            'context' => $this->context,
        ];
    }
}
