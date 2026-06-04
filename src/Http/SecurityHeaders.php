<?php
namespace Mnb\SecurityCore\Http;

class SecurityHeaders
{
    public function __construct(private array $config = []) {}

    public function apply(Response $response, ?string $cspNonce = null): Response
    {
        $response = $response
            ->withHeader('X-Content-Type-Options', $this->config['content_type_options'] ?? 'nosniff')
            ->withHeader('Referrer-Policy', $this->config['referrer_policy'] ?? 'strict-origin-when-cross-origin')
            ->withHeader('X-Frame-Options', 'SAMEORIGIN')
            ->withHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');

        $frameAncestors = $this->config['frame_ancestors'] ?? "'self'";
        $scriptSrc = "'self'" . ($cspNonce ? " 'nonce-{$cspNonce}'" : '');
        $csp = "default-src 'self'; script-src {$scriptSrc}; object-src 'none'; frame-ancestors {$frameAncestors}; base-uri 'self';";
        $response = $response->withHeader('Content-Security-Policy', $csp);

        if (!empty($this->config['hsts'])) {
            $response = $response->withHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
        }

        return $response;
    }
}
