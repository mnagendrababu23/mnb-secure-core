<?php
namespace Mnb\SecurityCore\Authorization;

use Mnb\SecurityCore\Auth\AuthContext;
use Mnb\SecurityCore\Authz\TenantContext;
use Mnb\SecurityCore\Authz\TenantGuard;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Logging\SecurityAuditEvent;
use Mnb\SecurityCore\Logging\SecurityAuditTrail;
use Mnb\SecurityCore\Trust\TrustBoundaryRegistry;
use Mnb\SecurityCore\Trust\TrustZoneResolver;

class AuthorizationRegistry
{
    /** @var array<string,AuthorizationPolicy> */
    private array $policies = [];
    private bool $denyByDefault = true;
    private bool $auditDenials = true;
    private bool $hideDenialReasons = true;

    /** @param array<string,AuthorizationPolicy|array<string,mixed>> $policies @param array<string,mixed> $config */
    public function __construct(array $policies = [], private array $config = [], private ?SecurityAuditTrail $audit = null, private ?TrustBoundaryRegistry $trustBoundaries = null, private ?TrustZoneResolver $zoneResolver = null)
    {
        foreach ($policies as $name => $policy) {
            $this->register(is_string($name) ? $name : (is_array($policy) ? (string)($policy['name'] ?? '') : $policy->name()), $policy);
        }
        $this->denyByDefault = (bool)($config['deny_by_default'] ?? true);
        $this->auditDenials = (bool)($config['audit_denials'] ?? true);
        $this->hideDenialReasons = (bool)($config['hide_denial_reasons'] ?? true);
        $this->zoneResolver ??= new TrustZoneResolver(is_array($config['zone_resolvers'] ?? null) ? $config : []);
    }

    public static function fromConfig(array $config, ?SecurityAuditTrail $audit = null, ?TrustBoundaryRegistry $trustBoundaries = null): self
    {
        $authz = is_array($config['authorization'] ?? null) ? $config['authorization'] : [];
        return new self(is_array($authz['policies'] ?? null) ? $authz['policies'] : [], $authz, $audit, $trustBoundaries, new TrustZoneResolver(is_array($config['trust_boundaries'] ?? null) ? $config['trust_boundaries'] : []));
    }

    public function register(string $name, AuthorizationPolicy|array $policy): void
    {
        if ($name === '') {
            throw new \InvalidArgumentException('Authorization policy name is required.');
        }
        $this->policies[$name] = $policy instanceof AuthorizationPolicy ? $policy : AuthorizationPolicy::fromArray($name, $policy);
    }

    public function has(string $name): bool { return isset($this->policies[$name]); }

    public function get(string $name): AuthorizationPolicy
    {
        if (!$this->has($name)) {
            throw new \InvalidArgumentException("Authorization policy '{$name}' is not registered.");
        }
        return $this->policies[$name];
    }

    /** @return array<string,AuthorizationPolicy> */ public function all(): array { return $this->policies; }

    /** @param array<string,mixed>|object|null $resource */
    public function decide(string $policyName, ?Request $request = null, array|object|null $resource = null, ?string $action = null, ?string $resourceName = null, ?string $dataClass = null, ?AuthContext $auth = null, ?TenantContext $tenant = null): AuthorizationDecision
    {
        $resourceArray = $this->resourceToArray($resource);

        if (!$this->has($policyName)) {
            $decision = AuthorizationDecision::deny($policyName, $action ?: $this->inferAction($policyName), $resourceName ?: $this->inferResourceName($policyName), 'authorization policy is not registered', AuthorizationAuditEvents::POLICY_MISSING, $this->auditDenials, [
                'deny_by_default' => $this->denyByDefault,
            ]);
            $this->auditDecision($decision, null, $resourceArray);
            return $this->denyByDefault ? $decision : AuthorizationDecision::allow($policyName, $action ?: 'access', $resourceName, false, ['policy_missing_allowed_by_config' => true]);
        }

        $policy = $this->get($policyName);
        $context = $request ? AuthorizationContext::fromRequest($request, $resourceArray, $resourceName, $action, $dataClass, $tenant) : new AuthorizationContext(auth: $auth, tenant: $tenant, resource: $resourceArray, resourceName: $resourceName, action: $action, dataClass: $dataClass);
        $auth = $auth ?: $context->authOrGuest();
        $tenant = $tenant ?: $context->tenant;
        $resourceName = $resourceName ?: $context->resourceName ?: $policy->resource() ?: $this->inferResourceName($policyName);
        $action = $action ?: $context->action ?: $this->inferAction($policyName);
        $dataClass = $dataClass ?: $context->dataClass;
        $zone = $context->resolvedZone($this->zoneResolver);

        $base = [
            'policy' => $policyName,
            'resource' => $resourceName,
            'action' => $action,
            'data_class' => $dataClass,
            'zone' => $zone,
            'user_id' => $auth->id(),
            'roles' => $auth->roles(),
            'permissions' => $auth->permissions(),
            'scopes' => $auth->scopes(),
            'tenant' => $tenant ? [
                'school_id' => $tenant->schoolId,
                'branch_id' => $tenant->branchId,
                'academic_year_id' => $tenant->academicYearId,
            ] : null,
        ];

        if (!$auth->isAuthenticated() && ($policy->roles() !== [] || $policy->permissions() !== [] || $policy->scopes() !== [] || $policy->tenantRequired())) {
            return $this->deny($policy, $action, $resourceName, 'authentication is required for this authorization policy', 'authentication_required', $context, $base, 401);
        }
        if (!$policy->allowsAction($action)) {
            return $this->deny($policy, $action, $resourceName, 'action is not allowed for this authorization policy', 'action_denied', $context, $base);
        }
        if (!$policy->allowsResource($resourceName)) {
            return $this->deny($policy, $action, $resourceName, 'resource is not allowed for this authorization policy', 'resource_denied', $context, $base);
        }
        if (!$policy->allowsDataClass($dataClass)) {
            return $this->deny($policy, $action, $resourceName, 'data class is not allowed for this authorization policy', 'data_class_denied', $context, $base);
        }
        if ($policy->roles() !== [] && !$auth->hasAnyRole($policy->roles())) {
            return $this->deny($policy, $action, $resourceName, 'required role is missing', AuthorizationAuditEvents::ROLE_DENIED, $context, $base);
        }
        if ($policy->scopes() !== [] && !$auth->hasAnyScope($policy->scopes())) {
            return $this->deny($policy, $action, $resourceName, 'required scope is missing', AuthorizationAuditEvents::SCOPE_DENIED, $context, $base);
        }
        if ($policy->permissions() !== [] && !$auth->canAny($policy->permissions())) {
            return $this->deny($policy, $action, $resourceName, 'required permission is missing', AuthorizationAuditEvents::PERMISSION_DENIED, $context, $base);
        }
        if ($policy->tenantRequired()) {
            if (!$tenant) {
                return $this->deny($policy, $action, $resourceName, 'tenant context is required', AuthorizationAuditEvents::TENANT_DENIED, $context, $base);
            }
            if ($resourceArray !== [] && !(new TenantGuard())->recordBelongsToContext($resourceArray, $tenant)) {
                return $this->deny($policy, $action, $resourceName, 'resource does not belong to tenant context', AuthorizationAuditEvents::TENANT_DENIED, $context, $base);
            }
        }
        if ($policy->trustBoundary() !== null && $this->trustBoundaries !== null) {
            $trust = $this->trustBoundaries->decide($policy->trustBoundary(), $request, $resourceArray, $action, $dataClass, $tenant, $auth, $resourceName);
            if ($trust->denied()) {
                return $this->deny($policy, $action, $resourceName, 'linked trust boundary denied: ' . $trust->reason(), 'trust_boundary_denied', $context, array_merge($base, ['trust_boundary' => $trust->toArray()]));
            }
        }

        $decision = AuthorizationDecision::allow($policyName, $action, $resourceName, $policy->audit(), $base);
        if ($policy->audit()) { $this->auditDecision($decision, $context, $resourceArray); }
        return $decision;
    }

    /** @param array<string,mixed> $record @return array<string,mixed> */
    public function filterReadableFields(string $policyName, ?Request $request, array $record): array
    {
        return $this->filterFields($policyName, $request, $record, 'read');
    }

    /** @param array<string,mixed> $record @return array<string,mixed> */
    public function filterWritableFields(string $policyName, ?Request $request, array $record): array
    {
        return $this->filterFields($policyName, $request, $record, 'write');
    }

    /** @param array<string,mixed> $record @return array<string,mixed> */
    private function filterFields(string $policyName, ?Request $request, array $record, string $mode): array
    {
        if (!$this->has($policyName)) { return []; }
        $policy = $this->get($policyName);
        $auth = $request?->attribute(AuthContext::ATTRIBUTE);
        return FieldAuthorization::filter($record, $policy, $auth instanceof AuthContext ? $auth : AuthContext::guest(), $mode);
    }

    /** @return array<string,mixed> */
    public function explain(string $policyName): array
    {
        return $this->has($policyName) ? PolicyExplainer::explain($this->get($policyName)) : ['name' => $policyName, 'registered' => false, 'deny_by_default' => $this->denyByDefault];
    }

    private function deny(AuthorizationPolicy $policy, string $action, ?string $resourceName, string $reason, string $code, AuthorizationContext $context, array $base, int $status = 403): AuthorizationDecision
    {
        $decision = AuthorizationDecision::deny($policy->name(), $action, $resourceName, $reason, $code, $this->auditDenials || $policy->audit(), $base, $status);
        if ($decision->auditRequired()) { $this->auditDecision($decision, $context, $context->resource); }
        return $decision;
    }

    /** @param array<string,mixed> $resource */
    private function auditDecision(AuthorizationDecision $decision, ?AuthorizationContext $context, array $resource): void
    {
        if (!$this->audit || !$decision->auditRequired()) { return; }
        $target = array_filter([
            'policy' => $decision->policyName(),
            'resource' => $decision->resourceName(),
            'resource_fingerprint' => $resource !== [] ? SecurityAuditEvent::fingerprint(json_encode($resource, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) ?: 'resource') : null,
        ], fn($value) => $value !== null && $value !== '');
        $this->audit->record(SecurityAuditEvent::make(
            'authorization',
            $decision->allowed() ? AuthorizationAuditEvents::ACCESS_ALLOWED : AuthorizationAuditEvents::ACCESS_DENIED,
            $decision->allowed() ? SecurityAuditEvent::OUTCOME_SUCCESS : SecurityAuditEvent::OUTCOME_DENIED,
            $decision->allowed() ? SecurityAuditEvent::SEVERITY_INFO : SecurityAuditEvent::SEVERITY_WARNING,
            $context?->actor() ?? [],
            $target,
            $context?->requestContext($decision->toArray()) ?? $decision->toArray(),
            ['reason' => $decision->reason(), 'code' => $decision->code()]
        ));
    }

    private function inferResourceName(string $policyName): ?string
    {
        $parts = explode('.', $policyName, 2);
        return $parts[0] !== '' ? $parts[0] : null;
    }

    private function inferAction(string $policyName): string
    {
        $parts = explode('.', $policyName);
        return count($parts) > 1 ? (string)end($parts) : 'access';
    }

    /** @return array<string,mixed> */
    private function resourceToArray(array|object|null $resource): array
    {
        if ($resource === null) { return []; }
        if (is_array($resource)) { return $resource; }
        return get_object_vars($resource);
    }
}
