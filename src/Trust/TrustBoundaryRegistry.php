<?php
namespace Mnb\SecurityCore\Trust;

use Mnb\SecurityCore\Auth\AuthContext;
use Mnb\SecurityCore\Authz\TenantContext;
use Mnb\SecurityCore\Authz\TenantGuard;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Logging\SecurityAuditEvent;
use Mnb\SecurityCore\Logging\SecurityAuditTrail;

class TrustBoundaryRegistry
{
    /** @var array<string,TrustBoundaryPolicy> */
    private array $policies = [];
    /** @var array<string,array<string,mixed>> */
    private array $resources = [];
    /** @var array<string,list<string>> */
    private array $zoneDataAccess = [];

    /** @param array<string,TrustBoundaryPolicy|array<string,mixed>> $policies @param array<string,mixed> $config */
    public function __construct(array $policies = [], private array $config = [], private ?SecurityAuditTrail $audit = null, private ?TrustZoneResolver $resolver = null)
    {
        foreach ($policies as $name => $policy) {
            $this->register(is_string($name) ? $name : (is_array($policy) ? (string)($policy['name'] ?? '') : $policy->name()), $policy);
        }
        $this->resources = is_array($config['resources'] ?? null) ? $config['resources'] : [];
        $this->zoneDataAccess = $this->buildZoneDataAccess(is_array($config['zone_data_access'] ?? null) ? $config['zone_data_access'] : []);
        $this->resolver ??= new TrustZoneResolver($config);
    }

    public static function fromConfig(array $config, ?SecurityAuditTrail $audit = null): self
    {
        $trust = is_array($config['trust_boundaries'] ?? null) ? $config['trust_boundaries'] : [];
        return new self(is_array($trust['rules'] ?? null) ? $trust['rules'] : [], $trust, $audit, new TrustZoneResolver($trust));
    }

    public function register(string $name, TrustBoundaryPolicy|array $policy): void
    {
        if ($name === '') {
            throw new \InvalidArgumentException('Trust boundary policy name is required.');
        }
        $this->policies[$name] = $policy instanceof TrustBoundaryPolicy ? $policy : TrustBoundaryPolicy::fromArray($name, $policy);
    }

    public function has(string $name): bool { return isset($this->policies[$name]); }

    public function get(string $name): TrustBoundaryPolicy
    {
        if (!$this->has($name)) {
            throw new \InvalidArgumentException("Trust boundary policy '{$name}' is not registered.");
        }
        return $this->policies[$name];
    }

    /** @return array<string,TrustBoundaryPolicy> */
    public function all(): array { return $this->policies; }

    /** @param array<string,mixed> $resource */
    public function decide(string $policyName, ?Request $request = null, array $resource = [], ?string $action = null, ?string $dataClass = null, ?TenantContext $tenant = null, ?AuthContext $auth = null, ?string $resourceName = null): TrustBoundaryDecision
    {
        if (!$this->has($policyName)) {
            $decision = TrustBoundaryDecision::deny($policyName, TrustZone::PUBLIC, $action ?: 'access', $dataClass ?: 'unknown', $resourceName, 'trust boundary policy is not registered', true);
            $this->auditDecision($decision, null, []);
            return $decision;
        }

        $policy = $this->get($policyName);
        $context = $request ? TrustBoundaryContext::fromRequest($request, $resource, $resourceName, $action, $dataClass, $tenant) : new TrustBoundaryContext(auth: $auth, tenant: $tenant, resource: $resource, resourceName: $resourceName, action: $action, dataClass: $dataClass);
        $auth = $auth ?: $context->auth ?: new AuthContext(false);
        $resourceName = $resourceName ?: $context->resourceName ?: ($policy->resources()[0] ?? $this->inferResourceName($policyName));
        $action = $action ?: $context->action ?: $this->inferAction($policyName, $policy);
        $dataClass = $dataClass ?: $context->dataClass ?: $this->resourceDataClass($resourceName) ?: ($policy->dataClasses()[0] ?? 'public');
        $zone = $context->zone ?: $this->resolver->resolve($request, $auth);

        $base = ['policy' => $policyName, 'resource' => $resourceName, 'action' => $action, 'data_class' => $dataClass, 'zone' => $zone];

        if (!$policy->allowsZone($zone)) {
            return $this->deny($policy, $zone, $action, $dataClass, $resourceName, 'zone is not allowed for this boundary policy', $context, $base);
        }
        if (!$policy->allowsResource($resourceName)) {
            return $this->deny($policy, $zone, $action, $dataClass, $resourceName, 'resource is not allowed for this boundary policy', $context, $base);
        }
        if (!$policy->allowsAction($action)) {
            return $this->deny($policy, $zone, $action, $dataClass, $resourceName, 'action is not allowed for this boundary policy', $context, $base);
        }
        if (!$policy->allowsDataClass($dataClass)) {
            return $this->deny($policy, $zone, $action, $dataClass, $resourceName, 'data class is not allowed for this boundary policy', $context, $base);
        }

        if ($policy->roles() !== [] && !$auth->hasAnyRole($policy->roles())) {
            return $this->deny($policy, $zone, $action, $dataClass, $resourceName, 'required role is missing', $context, $base);
        }
        if ($policy->scopes() !== [] && !$auth->hasAnyScope($policy->scopes())) {
            return $this->deny($policy, $zone, $action, $dataClass, $resourceName, 'required scope is missing', $context, $base);
        }
        if ($policy->permissions() !== [] && !$auth->canAny($policy->permissions())) {
            return $this->deny($policy, $zone, $action, $dataClass, $resourceName, 'required permission is missing', $context, $base);
        }

        if ($policy->tenantRequired()) {
            $tenant = $tenant ?: $context->tenant;
            if (!$tenant) {
                return $this->deny($policy, $zone, $action, $dataClass, $resourceName, 'tenant context is required', $context, $base);
            }
            if ($resource !== [] && !(new TenantGuard())->recordBelongsToContext($resource, $tenant)) {
                return $this->deny($policy, $zone, $action, $dataClass, $resourceName, 'resource does not belong to tenant context', $context, $base);
            }
        }

        $decision = TrustBoundaryDecision::allow($policyName, $zone, $action, $dataClass, $resourceName, $policy->audit(), $base);
        if ($policy->audit()) {
            $this->auditDecision($decision, $context, $resource);
        }
        return $decision;
    }

    /** @param array<string,mixed> $record @return array<string,mixed> */
    public function filterForZone(string $resourceName, array $record, string $zone): array
    {
        $fields = is_array($this->resources[$resourceName]['fields'] ?? null) ? $this->resources[$resourceName]['fields'] : [];
        if ($fields === []) {
            return $record;
        }
        $allowed = $this->zoneDataAccess[$zone] ?? $this->zoneDataAccess[TrustZone::PUBLIC] ?? ['public'];
        $filtered = [];
        foreach ($record as $key => $value) {
            $class = (string)($fields[$key] ?? ($this->config['deny_unclassified_fields'] ?? false ? 'highly_sensitive' : 'public'));
            if (in_array($class, $allowed, true)) {
                $filtered[$key] = $value;
            }
        }
        return $filtered;
    }

    private function deny(TrustBoundaryPolicy $policy, string $zone, string $action, string $dataClass, ?string $resourceName, string $reason, TrustBoundaryContext $context, array $base): TrustBoundaryDecision
    {
        $decision = TrustBoundaryDecision::deny($policy->name(), $zone, $action, $dataClass, $resourceName, $reason, true, $base);
        if ($policy->audit()) {
            $this->auditDecision($decision, $context, $context->resource);
        }
        return $decision;
    }

    /** @param array<string,mixed> $resource */
    private function auditDecision(TrustBoundaryDecision $decision, ?TrustBoundaryContext $context, array $resource): void
    {
        if (!$this->audit || !$decision->auditRequired()) {
            return;
        }
        $target = array_filter([
            'policy' => $decision->policyName(),
            'resource' => $decision->resourceName(),
            'resource_fingerprint' => $resource !== [] ? SecurityAuditEvent::fingerprint(json_encode($resource, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) ?: 'resource') : null,
        ], fn($value) => $value !== null && $value !== '');
        $this->audit->record(SecurityAuditEvent::make(
            'trust',
            'boundary.' . ($decision->allowed() ? 'allowed' : 'denied'),
            $decision->allowed() ? SecurityAuditEvent::OUTCOME_SUCCESS : SecurityAuditEvent::OUTCOME_DENIED,
            $decision->allowed() ? SecurityAuditEvent::SEVERITY_INFO : SecurityAuditEvent::SEVERITY_WARNING,
            $context?->actor() ?? [],
            $target,
            $context?->requestContext($decision->toArray()) ?? $decision->toArray(),
            ['reason' => $decision->reason()]
        ));
    }

    private function inferResourceName(string $policyName): ?string
    {
        $parts = explode('.', $policyName, 2);
        return $parts[0] !== '' ? $parts[0] : null;
    }

    private function inferAction(string $policyName, TrustBoundaryPolicy $policy): string
    {
        $parts = explode('.', $policyName);
        return count($parts) > 1 ? (string)end($parts) : ($policy->actions()[0] ?? 'access');
    }

    private function resourceDataClass(?string $resourceName): ?string
    {
        if (!$resourceName || !isset($this->resources[$resourceName]) || !is_array($this->resources[$resourceName])) {
            return null;
        }
        $class = $this->resources[$resourceName]['data_class'] ?? null;
        return is_scalar($class) ? (string)$class : null;
    }

    /** @param array<string,mixed> $configured @return array<string,list<string>> */
    private function buildZoneDataAccess(array $configured): array
    {
        $defaults = [
            TrustZone::PUBLIC => ['public'],
            TrustZone::AUTHENTICATED => ['public', 'internal'],
            TrustZone::SCHOOL_ADMIN => ['public', 'internal', 'confidential', 'sensitive'],
            TrustZone::SUPER_ADMIN => ['public', 'internal', 'confidential', 'sensitive'],
            TrustZone::INTERNAL_SYSTEM => ['public', 'internal', 'confidential', 'sensitive', 'highly_sensitive'],
        ];
        foreach ($configured as $zone => $classes) {
            if (is_array($classes)) {
                $defaults[(string)$zone] = array_values(array_filter(array_map('strval', $classes)));
            }
        }
        return $defaults;
    }
}
