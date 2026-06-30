<?php
namespace Mnb\SecurityCore\Http\Middleware;

use Mnb\SecurityCore\Contracts\MiddlewareInterface;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;
use Mnb\SecurityCore\Origin\OriginProtectionPolicy;
use Mnb\SecurityCore\Security\ServerIdentityHider;

class ServerIdentityProtectionMiddleware implements MiddlewareInterface
{
    private ServerIdentityHider $hider;
    private OriginProtectionPolicy $policy;

    public function __construct(private array $config = [])
    {
        $this->hider = new ServerIdentityHider($config);
        $this->policy = new OriginProtectionPolicy($config);
    }

    public function process(Request $request, callable $next): Response
    {
        if (!empty($this->config['enabled'])) {
            $decision = $this->policy->evaluateRequest($request);
            if (!$decision->allowed() || $decision->action() === 'redirect') {
                return $decision->toSafeResponse();
            }
        }

        $response = $next($request);

        if (empty($this->config['enabled'])) {
            return $response;
        }

        return $this->hider->sanitizeResponse($response);
    }
}
