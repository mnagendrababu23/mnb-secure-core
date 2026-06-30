<?php
namespace Mnb\SecurityCore\Files;

class FileSecurityDecision
{
    /** @param array<string,mixed> $context */
    public function __construct(
        private bool $allowed,
        private string $policyName,
        private string $action,
        private string $reason = 'allowed',
        private int $statusCode = 403,
        private bool $auditRequired = false,
        private array $context = [],
        private string $code = 'file_security_allowed'
    ) {}

    /** @param array<string,mixed> $context */
    public static function allow(string $policyName, string $action, bool $auditRequired = false, array $context = []): self
    {
        return new self(true, $policyName, $action, 'allowed', 200, $auditRequired, $context, 'file_security_allowed');
    }

    /** @param array<string,mixed> $context */
    public static function deny(string $policyName, string $action, string $reason, string $code = 'file_security_denied', bool $auditRequired = true, array $context = [], int $statusCode = 403): self
    {
        return new self(false, $policyName, $action, $reason, $statusCode, $auditRequired, $context, $code);
    }

    public function allowed(): bool { return $this->allowed; }
    public function denied(): bool { return !$this->allowed; }
    public function policyName(): string { return $this->policyName; }
    public function action(): string { return $this->action; }
    public function reason(): string { return $this->reason; }
    public function code(): string { return $this->code; }
    public function statusCode(): int { return $this->statusCode; }
    public function auditRequired(): bool { return $this->auditRequired; }
    public function safeMessage(): string { return $this->allowed ? 'Allowed' : 'File access denied'; }
    /** @return array<string,mixed> */ public function context(): array { return $this->context; }
    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return [
            'allowed' => $this->allowed,
            'policy' => $this->policyName,
            'action' => $this->action,
            'reason' => $this->reason,
            'code' => $this->code,
            'status_code' => $this->statusCode,
            'audit_required' => $this->auditRequired,
            'context' => $this->context,
        ];
    }
}
