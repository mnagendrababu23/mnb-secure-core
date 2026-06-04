<?php
namespace Mnb\SecurityCore\Http\Middleware;

use Mnb\SecurityCore\Contracts\MiddlewareInterface;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;
use Mnb\SecurityCore\Memory\MemoryGuard;

class MemoryLimitMiddleware implements MiddlewareInterface
{
    public function __construct(
        private MemoryGuard $guard,
        private string $operation = 'request'
    ) {}

    public function process(Request $request, callable $next): Response
    {
        $this->guard->assertWithinBudget($this->operation . ':before');
        $response = $next($request);
        $this->guard->assertWithinBudget($this->operation . ':after');
        $snapshot = $this->guard->snapshot($this->operation . ':response');
        return $response
            ->withHeader('X-Memory-Current-MB', (string)$snapshot->currentMb())
            ->withHeader('X-Memory-Peak-MB', (string)$snapshot->peakMb());
    }
}
