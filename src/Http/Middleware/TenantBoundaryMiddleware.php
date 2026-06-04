<?php
namespace Mnb\SecurityCore\Http\Middleware;

use Mnb\SecurityCore\Authz\TenantContext;
use Mnb\SecurityCore\Authz\TenantGuard;
use Mnb\SecurityCore\Contracts\MiddlewareInterface;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;

class TenantBoundaryMiddleware implements MiddlewareInterface
{
    public function __construct(private TenantGuard $guard, private TenantContext $context, private array $record) {}

    public function process(Request $request, callable $next): Response
    {
        if (!$this->guard->recordBelongsToContext($this->record, $this->context)) {
            return Response::json(['status' => false, 'message' => 'Tenant boundary violation'], 403);
        }
        return $next($request);
    }
}
