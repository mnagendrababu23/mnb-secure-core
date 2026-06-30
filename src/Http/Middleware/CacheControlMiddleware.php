<?php
namespace Mnb\SecurityCore\Http\Middleware;

use Mnb\SecurityCore\Contracts\MiddlewareInterface;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;
use Mnb\SecurityCore\Web\CacheControlPolicy;

class CacheControlMiddleware implements MiddlewareInterface
{
    public function __construct(private CacheControlPolicy $policy, private string $profile = 'private_user') {}

    public function process(Request $request, callable $next): Response
    {
        $response = $next($request);
        foreach ($this->policy->headers($this->profile) as $name => $value) {
            $response = $response->withHeader($name, $value);
        }
        return $response;
    }
}
