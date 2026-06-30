<?php
namespace Mnb\SecurityCore\Http\Middleware;

use Mnb\SecurityCore\Contracts\MiddlewareInterface;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;
use Mnb\SecurityCore\Http\SecurityHeaders;
use Mnb\SecurityCore\Http\SecurityHeadersBuilder;
use Mnb\SecurityCore\Security\CspNonceManager;

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
        $nonce = null;

        if ($this->nonceResolver === null && SecurityHeadersBuilder::wantsAutoNonce($this->config)) {
            $nonce = (new CspNonceManager())->nonce();
            $request = $request->withAttribute(CspNonceManager::REQUEST_ATTRIBUTE, $nonce)
                ->withAttribute('csp_nonce', $nonce);
        }

        $response = $next($request);

        if ($this->nonceResolver) {
            $resolved = ($this->nonceResolver)($request, $response);
            $nonce = is_string($resolved) && $resolved !== '' ? $resolved : null;
        } elseif ($nonce === null) {
            $resolved = $request->attribute(CspNonceManager::REQUEST_ATTRIBUTE) ?? $request->attribute('csp_nonce');
            $nonce = is_string($resolved) && $resolved !== '' ? $resolved : null;
        }

        return (new SecurityHeaders($this->config))->apply($response, $nonce, $request);
    }
}
