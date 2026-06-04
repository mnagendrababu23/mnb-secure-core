<?php
namespace Mnb\SecurityCore\Http\Middleware;

use Mnb\SecurityCore\Contracts\MiddlewareInterface;
use Mnb\SecurityCore\Errors\SafeErrorHandler;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;
use Throwable;

class ErrorHandlingMiddleware implements MiddlewareInterface
{
    public function __construct(private SafeErrorHandler $handler) {}

    public function process(Request $request, callable $next): Response
    {
        try {
            return $next($request);
        } catch (Throwable $throwable) {
            return $this->handler->renderThrowable($throwable, $request, ['caught_by' => self::class]);
        }
    }
}
