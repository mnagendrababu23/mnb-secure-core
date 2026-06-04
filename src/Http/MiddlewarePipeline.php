<?php
namespace Mnb\SecurityCore\Http;

use Mnb\SecurityCore\Contracts\MiddlewareInterface;

class MiddlewarePipeline
{
    /** @var MiddlewareInterface[] */
    private array $middleware;

    public function __construct(array $middleware = [])
    {
        $this->middleware = $middleware;
    }

    public function pipe(MiddlewareInterface $middleware): self
    {
        $clone = clone $this;
        $clone->middleware[] = $middleware;
        return $clone;
    }

    public function handle(Request $request, callable $destination): Response
    {
        $pipeline = array_reduce(
            array_reverse($this->middleware),
            fn($next, MiddlewareInterface $middleware) => fn(Request $request) => $middleware->process($request, $next),
            $destination
        );

        return $pipeline($request);
    }
}
