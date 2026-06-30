<?php
namespace Mnb\SecurityCore\Http\Middleware;

use Mnb\SecurityCore\Auth\OpaqueTokenService;
use Mnb\SecurityCore\Contracts\MiddlewareInterface;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;

class ApiTokenMiddleware implements MiddlewareInterface
{
    public function __construct(private OpaqueTokenService $tokens) {}

    public function process(Request $request, callable $next): Response
    {
        $plainToken = $request->bearerToken();
        if (!$plainToken) {
            return Response::json(['status' => false, 'message' => 'Missing bearer token'], 401);
        }
        $record = $this->tokens->validate($plainToken, $request->ip(), (string)$request->header('user-agent', ''));
        if (!$record) {
            return Response::json(['status' => false, 'message' => 'Invalid or expired token'], 401);
        }

        $request = $request
            ->withAttribute('auth_token', $record)
            ->withAttribute('auth_user_id', $record['user_id'] ?? null)
            ->withAttribute('auth_scopes', $record['scopes'] ?? []);

        return $next($request);
    }
}
