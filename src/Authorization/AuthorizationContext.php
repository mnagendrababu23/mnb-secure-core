<?php
namespace Mnb\SecurityCore\Authorization;

use Mnb\SecurityCore\Auth\AuthContext;
use Mnb\SecurityCore\Authz\TenantContext;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Trust\TrustZone;
use Mnb\SecurityCore\Trust\TrustZoneResolver;

class AuthorizationContext
{
    /** @param array<string,mixed> $resource */
    public function __construct(
        public readonly ?Request $request = null,
        public readonly ?AuthContext $auth = null,
        public readonly ?TenantContext $tenant = null,
        public readonly array $resource = [],
        public readonly ?string $resourceName = null,
        public readonly ?string $action = null,
        public readonly ?string $dataClass = null,
        public readonly ?string $zone = null
    ) {}

    /** @param array<string,mixed> $resource */
    public static function fromRequest(Request $request, array $resource = [], ?string $resourceName = null, ?string $action = null, ?string $dataClass = null, ?TenantContext $tenant = null): self
    {
        $auth = $request->attribute(AuthContext::ATTRIBUTE);
        $tenantContext = $tenant ?: $request->attribute('tenant_context');
        $zone = $request->attribute('trust_zone');
        return new self(
            $request,
            $auth instanceof AuthContext ? $auth : AuthContext::guest(),
            $tenantContext instanceof TenantContext ? $tenantContext : null,
            $resource,
            $resourceName,
            $action,
            $dataClass,
            is_string($zone) ? $zone : null
        );
    }

    public function authOrGuest(): AuthContext
    {
        return $this->auth ?: AuthContext::guest();
    }

    public function resolvedZone(?TrustZoneResolver $resolver = null): string
    {
        if ($this->zone) { return $this->zone; }
        $resolver ??= new TrustZoneResolver();
        return $resolver->resolve($this->request, $this->authOrGuest());
    }

    /** @return array<string,mixed> */
    public function actor(): array
    {
        $auth = $this->authOrGuest();
        return array_filter([
            'user_id' => $auth->id(),
            'roles' => $auth->roles(),
            'scopes' => $auth->scopes(),
            'permissions' => $auth->permissions(),
            'zone' => $this->zone,
            'school_id' => $this->tenant?->schoolId,
            'branch_id' => $this->tenant?->branchId,
            'academic_year_id' => $this->tenant?->academicYearId,
        ], fn($value) => $value !== null && $value !== []);
    }

    /** @return array<string,mixed> */
    public function requestContext(array $extra = []): array
    {
        return array_filter(array_merge([
            'method' => $this->request?->method(),
            'path' => $this->request?->path(),
            'client_ip' => $this->request?->clientIp(),
            'request_id' => $this->request?->attribute('request_id'),
            'resource' => $this->resourceName,
            'action' => $this->action,
            'data_class' => $this->dataClass,
        ], $extra), fn($value) => $value !== null && $value !== '');
    }
}
