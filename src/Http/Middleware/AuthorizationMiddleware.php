<?php
namespace Mnb\SecurityCore\Http\Middleware;

use Mnb\SecurityCore\Authorization\AuthorizationRegistry;
use Mnb\SecurityCore\Authorization\ResourceResolverInterface;
use Mnb\SecurityCore\Contracts\MiddlewareInterface;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;

class AuthorizationMiddleware implements MiddlewareInterface
{
    public function __construct(
        private AuthorizationRegistry $authorization,
        private string $policyName,
        private mixed $resourceResolver = null,
        private ?string $action = null,
        private ?string $resourceName = null,
        private ?string $dataClass = null,
        private bool $hideReason = true
    ) {}

    public function process(Request $request, callable $next): Response
    {
        $resource = $this->resolveResource($request);
        $decision = $this->authorization->decide($this->policyName, $request, $resource, $this->action, $this->resourceName, $this->dataClass);
        if ($decision->denied()) {
            return Response::json([
                'status' => false,
                'message' => $this->hideReason ? $decision->safeMessage() : $decision->reason(),
                'code' => $decision->code(),
            ], $decision->statusCode());
        }
        $request = $request
            ->withAttribute('authorization_decision', $decision)
            ->withAttribute('authorization_policy', $this->policyName);
        return $next($request);
    }

    private function resolveResource(Request $request): array|object|null
    {
        if ($this->resourceResolver instanceof ResourceResolverInterface) {
            return $this->resourceResolver->resolve($request, $this->policyName);
        }
        if (is_callable($this->resourceResolver)) {
            return ($this->resourceResolver)($request, $this->policyName);
        }
        return null;
    }
}
