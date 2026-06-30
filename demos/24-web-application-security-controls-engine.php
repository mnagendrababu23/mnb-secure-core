<?php
require_once __DIR__ . '/_demo_bootstrap.php';

use Mnb\SecurityCore\Core\SecurityKernel;
use Mnb\SecurityCore\Http\MiddlewarePipeline;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;

demo_title('24. Web Application Security Controls Engine');

$config = require __DIR__ . '/../config/security.php';
$config['app']['key'] = str_repeat('W', 40);
$config['web_security']['signed_urls']['key'] = str_repeat('S', 40);
$config['web_security']['cookies']['secure'] = true;
$config['web_security']['profiles']['browser_form']['cache_policy'] = 'sensitive_no_store';

$kernel = new SecurityKernel($config);
$controls = $kernel->webSecurityControls('browser_form');

$escaped = $controls->escapeHtml('<img src=x onerror=alert(1)>');
$clean = $controls->sanitizeHtml('<p onclick="x">Hello <script>alert(1)</script><a href="javascript:bad()">bad</a><a href="/ok">ok</a></p>');
$redirect = $controls->safeRedirect('https://evil.test', '/dashboard');
$cookie = $controls->cookies()->make('__Host-demo', 'abc 123', ['max_age' => 300]);
$signed = $controls->signedUrl()->sign('/download/report.csv', ['user_id' => 10], time() + 300, 'download');

$response = (new MiddlewarePipeline([
    $kernel->cacheControlMiddleware($controls->profile()->cachePolicy()),
]))->handle(new Request('GET', '/account'), fn() => Response::text('account'));

demo_step('Escaped HTML', $escaped);
demo_step('Sanitized HTML', $clean);
demo_step('Safe redirect fallback', $redirect);
demo_step('Secure cookie header', $cookie);
demo_step('Signed URL verifies', $controls->signedUrl()->verify($signed, 'download') ? 'YES' : 'NO');
demo_step('Cache headers', $response->headers());

demo_result(
    str_contains($escaped, '&lt;img')
    && !str_contains($clean, 'script')
    && !str_contains($clean, 'onclick')
    && !str_contains($clean, 'javascript:')
    && $redirect === '/dashboard'
    && str_contains($cookie, 'Secure')
    && str_contains($cookie, 'HttpOnly')
    && $controls->signedUrl()->verify($signed, 'download')
    && (($response->headers()['Cache-Control'] ?? '') === 'no-store, private'),
    'Web controls escape output, sanitize HTML, block open redirects, set secure cookies, sign URLs, and apply cache policy.'
);
