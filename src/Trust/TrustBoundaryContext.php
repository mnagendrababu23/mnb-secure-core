<?php
namespace Mnb\SecurityCore\Trust;

use Mnb\SecurityCore\Auth\AuthContext;
use Mnb\SecurityCore\Auth\PermissionGuard as AuthPermissionGuard;
use Mnb\SecurityCore\Authz\TenantContext;
use Mnb\SecurityCore\Http\Request;

class TrustBoundaryContext
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
        $auth = AuthPermissionGuard::context($request);
        $tenantContext = $tenant ?: $request->attribute('tenant_context');
        return new self(
            request: $request,
            auth: $auth,
            tenant: $tenantContext instanceof TenantContext ? $tenantContext : null,
            resource: $resource,
            resourceName: $resourceName,
            action: $action,
            dataClass: $dataClass,
            zone: is_string($request->attribute('trust_zone')) ? (string)$request->attribute('trust_zone') : null
        );
    }

    /** @return array<string,mixed> */
    public function actor(): array
    {
        $actor = [];
        if ($this->auth?->id() !== null) {
            $actor['user_id'] = $this->auth->id();
        }
        if ($this->auth?->roles()) {
            $actor['roles'] = $this->auth->roles();
        }
        return $actor;
    }

    /** @return array<string,mixed> */
    public function requestContext(array $extra = []): array
    {
        if (!$this->request) {
            return $extra;
        }
        return array_filter([
            'ip' => $this->request->ip(),
            'remote_ip' => method_exists($this->request, 'remoteIp') ? $this->request->remoteIp() : null,
            'method' => $this->request->method(),
            'path' => $this->request->path(),
            'host' => method_exists($this->request, 'effectiveHost') ? $this->request->effectiveHost() : null,
        ] + $extra, fn($value) => $value !== null && $value !== '');
    }
}
