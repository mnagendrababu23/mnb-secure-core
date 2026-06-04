<?php
require_once __DIR__ . '/_demo_bootstrap.php';

use Mnb\SecurityCore\Security\WebSecurityControls;
use Mnb\SecurityCore\Security\CspNonceManager;
use Mnb\SecurityCore\Http\SecurityHeaders;
use Mnb\SecurityCore\Http\Response;

demo_title('06. Web Application Security Controls');

$unsafe = '<script>alert("xss")</script><b>Student</b>';
$escaped = WebSecurityControls::escape($unsafe);
$safeRedirect = WebSecurityControls::validateRedirect('/dashboard', '/');
$blockedRedirect = WebSecurityControls::validateRedirect('https://evil.example/phish', '/');

$nonce = new CspNonceManager();
$response = (new SecurityHeaders(['hsts' => true, 'frame_ancestors' => "'self'"]))->apply(Response::text('demo'), $nonce->nonce());

demo_step('Escaped HTML', $escaped);
demo_step('Valid internal redirect', $safeRedirect);
demo_step('Blocked external redirect fallback', $blockedRedirect);
demo_step('Security headers', $response->headers());
demo_step('CSP nonce attribute', $nonce->attribute());

demo_result(
    str_contains($escaped, '&lt;script&gt;')
    && $safeRedirect === '/dashboard'
    && $blockedRedirect === '/'
    && isset($response->headers()['Content-Security-Policy']),
    'Escaping, redirect validation, CSP nonce, and secure headers are working.'
);
