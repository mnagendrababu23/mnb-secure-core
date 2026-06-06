<?php
namespace Mnb\SecurityCore\Http\Middleware;

use Mnb\SecurityCore\Contracts\MiddlewareInterface;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;
use Mnb\SecurityCore\Http\SecurityHeaders;

class SecurityHeadersMiddleware implements MiddlewareInterface
{
    /** @var callable|null */
    private $nonceResolver;

    public function __construct(
        private array $config = [],
        ?callable $nonceResolver = null
    ) {
        $this->nonceResolver = $nonceResolver;
    }

    public function process(Request $request, callable $next): Response
    {
        $response = $next($request);
        $nonce = null;
        if ($this->nonceResolver) {
            $resolved = ($this->nonceResolver)($request, $response);
            $nonce = is_string($resolved) && $resolved !== '' ? $resolved : null;
        }

        return (new SecurityHeaders($this->config))->apply($response, $nonce);
    }
}
