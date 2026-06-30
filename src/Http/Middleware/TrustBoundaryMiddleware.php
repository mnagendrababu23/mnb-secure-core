<?php
namespace Mnb\SecurityCore\Http\Middleware;

use Mnb\SecurityCore\Contracts\MiddlewareInterface;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;
use Mnb\SecurityCore\Trust\TrustBoundaryRegistry;

class TrustBoundaryMiddleware implements MiddlewareInterface
{
    /** @param callable|null $resourceResolver callable(Request): array<string,mixed> */
    public function __construct(
        private TrustBoundaryRegistry $registry,
        private string $policyName,
        private $resourceResolver = null,
        private ?string $action = null,
        private ?string $dataClass = null,
        private ?string $resourceName = null,
        private bool $hideReason = true
    ) {}

    public function process(Request $request, callable $next): Response
    {
        $resource = [];
        if (is_callable($this->resourceResolver)) {
            $resolved = ($this->resourceResolver)($request);
            if (is_array($resolved)) {
                $resource = $resolved;
            }
        }

        $decision = $this->registry->decide($this->policyName, $request, $resource, $this->action, $this->dataClass, resourceName: $this->resourceName);
        if ($decision->denied()) {
            return Response::json([
                'status' => false,
                'message' => $this->hideReason ? 'Access denied by trust boundary' : $decision->reason(),
                'boundary' => [
                    'policy' => $decision->policyName(),
                    'zone' => $decision->zone(),
                    'resource' => $decision->resourceName(),
                    'action' => $decision->action(),
                ],
            ], 403);
        }

        return $next(
            $request
                ->withAttribute('trust_boundary_decision', $decision)
                ->withAttribute('trust_zone', $decision->zone())
        );
    }
}
