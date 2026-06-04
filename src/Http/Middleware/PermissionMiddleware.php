<?php
namespace Mnb\SecurityCore\Http\Middleware;

use Mnb\SecurityCore\Authz\PermissionGuard;
use Mnb\SecurityCore\Authz\TenantContext;
use Mnb\SecurityCore\Contracts\MiddlewareInterface;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;

class PermissionMiddleware implements MiddlewareInterface
{
    public function __construct(private PermissionGuard $guard, private TenantContext $context, private string $permission) {}

    public function process(Request $request, callable $next): Response
    {
        if (!$this->guard->can($this->context, $this->permission)) {
            return Response::json(['status' => false, 'message' => 'Forbidden'], 403);
        }
        return $next($request);
    }
}
