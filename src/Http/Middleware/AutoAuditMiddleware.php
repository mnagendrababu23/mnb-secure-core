<?php
namespace Mnb\SecurityCore\Http\Middleware;

use Mnb\SecurityCore\Contracts\MiddlewareInterface;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;
use Mnb\SecurityCore\Logging\AutoAuditLogger;
use Mnb\SecurityCore\Logging\SecurityAuditTrail;

class AutoAuditMiddleware implements MiddlewareInterface
{
    private AutoAuditLogger $logger;

    public function __construct(AutoAuditLogger|SecurityAuditTrail $audit, private array $config = [])
    {
        $this->logger = $audit instanceof AutoAuditLogger ? $audit : new AutoAuditLogger($audit, $config);
    }

    public function process(Request $request, callable $next): Response
    {
        if (array_key_exists('enabled', $this->config) && $this->config['enabled'] === false) {
            return $next($request);
        }

        try {
            $response = $next($request);
            $this->logger->recordRequest($request, $response->status());
            return $response;
        } catch (\Throwable $e) {
            $this->logger->recordAction(
                $this->logger->inferAction($request) ?: 'request.exception',
                'failure',
                AutoAuditLogger::actorFromRequest($request),
                ['path' => $request->path(), 'method' => $request->method()],
                \Mnb\SecurityCore\Logging\SecurityAuditEvent::contextFromRequest($request),
                ['exception' => $e::class, 'auto' => true]
            );
            throw $e;
        }
    }
}
