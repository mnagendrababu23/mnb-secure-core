<?php
namespace Mnb\SecurityCore\Http;

class SecurityHeaders
{
    public function __construct(private array $config = []) {}

    public function apply(Response $response, ?string $cspNonce = null, ?Request $request = null): Response
    {
        foreach ((new SecurityHeadersBuilder($this->config))->headers($cspNonce, $request) as $name => $value) {
            $response = $response->withHeader($name, $value);
        }
        return $response;
    }

    public function build(?string $cspNonce = null, ?Request $request = null): array
    {
        return (new SecurityHeadersBuilder($this->config))->headers($cspNonce, $request);
    }
}
