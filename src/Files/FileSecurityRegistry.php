<?php
namespace Mnb\SecurityCore\Files;

use Mnb\SecurityCore\Auth\AuthContext;
use Mnb\SecurityCore\Authz\TenantContext;
use Mnb\SecurityCore\Authz\TenantGuard;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Logging\SecurityAuditEvent;
use Mnb\SecurityCore\Logging\SecurityAuditTrail;

class FileSecurityRegistry
{
    /** @param array<string,FileSecurityPolicy> $policies */
    public function __construct(
        private array $policies,
        private bool $enabled = true,
        private bool $denyByDefault = true,
        private bool $auditDownloads = true,
        private ?SecurityAuditTrail $audit = null
    ) {}

    /** @param array<string,mixed> $config */
    public static function fromConfig(array $config, ?SecurityAuditTrail $audit = null): self
    {
        $fs = is_array($config['file_security'] ?? null) ? $config['file_security'] : [];
        $policies = [];
        foreach ((array)($fs['policies'] ?? []) as $name => $policy) {
            if (is_string($name) && is_array($policy)) {
                $policies[$name] = FileSecurityPolicy::fromArray($name, $policy);
            }
        }
        if ($policies === []) {
            $policies['files.download'] = FileSecurityPolicy::fromArray('files.download', [
                'actions' => ['download'],
                'roles' => [],
                'permissions' => [],
                'scopes' => [],
                'tenant_required' => false,
                'data_classes' => ['public', 'internal'],
                'audit' => true,
            ]);
        }
        return new self(
            $policies,
            (bool)($fs['enabled'] ?? true),
            (bool)($fs['deny_by_default'] ?? true),
            (bool)($fs['audit_downloads'] ?? true),
            $audit
        );
    }

    public function has(string $name): bool { return isset($this->policies[$name]); }
    public function get(string $name): FileSecurityPolicy
    {
        if (!$this->has($name)) {
            throw new \InvalidArgumentException("File security policy '{$name}' is not registered.");
        }
        return $this->policies[$name];
    }

    public function decide(string $policyName, ?Request $request, array|FileSecurityRecord $fileRecord, string $action = 'download'): FileSecurityDecision
    {
        $record = $fileRecord instanceof FileSecurityRecord ? $fileRecord : FileSecurityRecord::fromArray($fileRecord);
        if (!$this->enabled) {
            return FileSecurityDecision::allow($policyName, $action, false, ['file_security_disabled' => true]);
        }
        if (!$this->has($policyName)) {
            $decision = FileSecurityDecision::deny($policyName, $action, 'file security policy is not registered', 'file_policy_missing', true, ['deny_by_default' => $this->denyByDefault]);
            $this->auditDecision($decision, $request, $record);
            return $this->denyByDefault ? $decision : FileSecurityDecision::allow($policyName, $action, false, ['policy_missing_allowed_by_config' => true]);
        }
        $policy = $this->get($policyName);
        $auth = $request?->attribute(AuthContext::ATTRIBUTE);
        if (!$auth instanceof AuthContext) { $auth = AuthContext::guest(); }
        $tenant = $request?->attribute('tenant_context');
        if (!$tenant instanceof TenantContext) { $tenant = null; }

        $base = [
            'policy' => $policyName,
            'action' => $action,
            'file_id' => $record->fileId(),
            'profile' => $record->profile(),
            'data_class' => $record->dataClass(),
            'scan_status' => $record->scanStatus(),
            'user_id' => $auth->id(),
            'tenant_required' => $policy->tenantRequired(),
        ];

        if (!$policy->allowsAction($action)) {
            return $this->deny($policy, $request, $record, $action, 'action is not allowed for this file policy', 'file_action_denied', $base);
        }
        if ($policy->requireScanPassed() && $record->scanStatus() !== 'passed') {
            return $this->deny($policy, $request, $record, $action, 'file scan has not passed', 'file_scan_not_passed', $base);
        }
        if (!$policy->allowsDataClass($record->dataClass())) {
            return $this->deny($policy, $request, $record, $action, 'file data class is not allowed for this policy', 'file_data_class_denied', $base);
        }
        if (($policy->roles() !== [] || $policy->permissions() !== [] || $policy->scopes() !== []) && !$auth->isAuthenticated()) {
            return $this->deny($policy, $request, $record, $action, 'authentication is required for this file policy', 'file_authentication_required', $base, 401);
        }
        if ($policy->roles() !== [] && !$auth->hasAnyRole($policy->roles())) {
            return $this->deny($policy, $request, $record, $action, 'required file role is missing', 'file_role_denied', $base);
        }
        if ($policy->scopes() !== [] && !$auth->hasAnyScope($policy->scopes())) {
            return $this->deny($policy, $request, $record, $action, 'required file scope is missing', 'file_scope_denied', $base);
        }
        if ($policy->permissions() !== [] && !$auth->canAny($policy->permissions())) {
            return $this->deny($policy, $request, $record, $action, 'required file permission is missing', 'file_permission_denied', $base);
        }
        if ($policy->tenantRequired()) {
            if (!$tenant) {
                return $this->deny($policy, $request, $record, $action, 'tenant context is required for file access', 'file_tenant_required', $base);
            }
            $resource = $record->tenantResource();
            if ($resource !== [] && !(new TenantGuard())->recordBelongsToContext($resource, $tenant)) {
                return $this->deny($policy, $request, $record, $action, 'file does not belong to tenant context', 'file_tenant_denied', $base);
            }
        }
        $decision = FileSecurityDecision::allow($policyName, $action, $policy->audit() || $this->auditDownloads, $base);
        $this->auditDecision($decision, $request, $record);
        return $decision;
    }

    private function deny(FileSecurityPolicy $policy, ?Request $request, FileSecurityRecord $record, string $action, string $reason, string $code, array $context = [], int $status = 403): FileSecurityDecision
    {
        $decision = FileSecurityDecision::deny($policy->name(), $action, $reason, $code, $policy->audit() || $this->auditDownloads, $context, $status);
        $this->auditDecision($decision, $request, $record);
        return $decision;
    }

    private function auditDecision(FileSecurityDecision $decision, ?Request $request, FileSecurityRecord $record): void
    {
        if (!$this->audit || !$decision->auditRequired()) { return; }
        $actor = [];
        $auth = $request?->attribute(AuthContext::ATTRIBUTE);
        if ($auth instanceof AuthContext && $auth->id() !== null) { $actor['user_id'] = $auth->id(); }
        $target = array_filter([
            'policy' => $decision->policyName(),
            'file_id' => $record->fileId(),
            'storage_fingerprint' => SecurityAuditEvent::fingerprint($record->storagePath()),
            'original_name' => $record->originalName(),
            'profile' => $record->profile(),
        ], fn(mixed $value): bool => $value !== null && $value !== '');
        $context = $request ? SecurityAuditTrail::contextFromRequest($request, $decision->context()) : $decision->context();
        $this->audit->record(SecurityAuditEvent::make(
            'file',
            'access.' . $decision->action(),
            $decision->allowed() ? SecurityAuditEvent::OUTCOME_SUCCESS : SecurityAuditEvent::OUTCOME_DENIED,
            $decision->allowed() ? SecurityAuditEvent::SEVERITY_INFO : SecurityAuditEvent::SEVERITY_WARNING,
            $actor,
            $target,
            $context,
            ['code' => $decision->code(), 'reason' => $decision->reason()]
        ));
    }
}
