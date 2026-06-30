<?php
namespace Mnb\SecurityCore\Http;

use Mnb\SecurityCore\Contracts\MiddlewareInterface;

class SecureRequestReceiver
{
    /** @param list<MiddlewareInterface> $middleware */
    public function __construct(private RequestReceivingProfile $profile, private array $middleware = []) {}

    public function profile(): RequestReceivingProfile
    {
        return $this->profile;
    }

    public function pipeline(): MiddlewarePipeline
    {
        return new MiddlewarePipeline($this->middleware);
    }

    public function handle(Request $request, callable $destination): Response
    {
        $request = $request->withAttribute('request_receiving_profile', $this->profile->name());
        return $this->pipeline()->handle($request, $destination);
    }
}
