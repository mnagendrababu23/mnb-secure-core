<?php
namespace Mnb\SecurityCore\Trust;

class TrustBoundaryDecision
{
    /** @param array<string,mixed> $context */
    public function __construct(
        private bool $allowed,
        private string $policyName,
        private string $zone,
        private string $action,
        private string $dataClass,
        private ?string $resourceName = null,
        private string $reason = 'allowed',
        private bool $auditRequired = false,
        private array $context = []
    ) {}

    /** @param array<string,mixed> $context */
    public static function allow(string $policyName, string $zone, string $action, string $dataClass, ?string $resourceName = null, bool $auditRequired = false, array $context = []): self
    {
        return new self(true, $policyName, $zone, $action, $dataClass, $resourceName, 'allowed', $auditRequired, $context);
    }

    /** @param array<string,mixed> $context */
    public static function deny(string $policyName, string $zone, string $action, string $dataClass, ?string $resourceName, string $reason, bool $auditRequired = true, array $context = []): self
    {
        return new self(false, $policyName, $zone, $action, $dataClass, $resourceName, $reason, $auditRequired, $context);
    }

    public function allowed(): bool { return $this->allowed; }
    public function denied(): bool { return !$this->allowed; }
    public function policyName(): string { return $this->policyName; }
    public function zone(): string { return $this->zone; }
    public function action(): string { return $this->action; }
    public function dataClass(): string { return $this->dataClass; }
    public function resourceName(): ?string { return $this->resourceName; }
    public function reason(): string { return $this->reason; }
    public function auditRequired(): bool { return $this->auditRequired; }

    /** @return array<string,mixed> */
    public function context(): array { return $this->context; }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return [
            'allowed' => $this->allowed,
            'policy' => $this->policyName,
            'zone' => $this->zone,
            'action' => $this->action,
            'data_class' => $this->dataClass,
            'resource' => $this->resourceName,
            'reason' => $this->reason,
            'audit_required' => $this->auditRequired,
            'context' => $this->context,
        ];
    }
}
