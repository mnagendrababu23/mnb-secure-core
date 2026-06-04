<?php
require_once __DIR__ . '/../../_demo_bootstrap.php';

use Mnb\SecurityCore\Security\WebSecurityControls;
use Mnb\SecurityCore\Security\CspNonceManager;
use Mnb\SecurityCore\Http\Response;
use Mnb\SecurityCore\Http\SecurityHeaders;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\MiddlewarePipeline;
use Mnb\SecurityCore\Http\Middleware\RequestSizeMiddleware;
use Mnb\SecurityCore\Http\Middleware\RateLimitMiddleware;
use Mnb\SecurityCore\RateLimit\FileRateLimiter;

$request = Request::fromGlobals();
$nonce = new CspNonceManager();
$limiter = new FileRateLimiter(demo_storage_path('web-demo-rate'));
$pipeline = new MiddlewarePipeline([
    new RequestSizeMiddleware(1024 * 1024),
    new RateLimitMiddleware($limiter, 60, 60, 'web-demo-' . getmypid()),
]);

$response = $pipeline->handle($request, function () use ($nonce) {
    $unsafe = '<script>alert("xss")</script>Student Portal';
    $escaped = WebSecurityControls::escape($unsafe);
    $items = [
        'Trust Zones and Data Boundaries',
        'Secure Request Receiving Strategy',
        'Authentication Strategy',
        'Authorization Strategy',
        'Data Protection Strategy',
        'Web Security Controls',
        'API Security and Rate Limiting',
        'File Upload/Download Security',
        'Caching Strategy',
        'Environment and Secret Management',
        'Logging, Audit, and Monitoring',
        'Backup, Recovery, and Incident Response',
        'Vulnerability Blocking Matrix',
    ];
    $lis = '';
    foreach ($items as $item) {
        $lis .= '<li>' . WebSecurityControls::escape($item) . '</li>';
    }
    $body = '<!doctype html><html><head><meta charset="utf-8"><title>MNB Secure Core Demo</title>'
        . '<style nonce="' . WebSecurityControls::escape($nonce->nonce()) . '">body{font-family:Arial,sans-serif;margin:40px;line-height:1.55;color:#172033}.wrap{max-width:980px;margin:auto}.badge{display:inline-block;background:#eef4ff;color:#2455c3;border-radius:999px;padding:6px 12px;font-weight:700}.box{border:1px solid #dbe5ff;border-radius:16px;padding:20px;margin-top:16px;background:#fbfdff}code{background:#f3f5f8;padding:2px 6px;border-radius:6px}</style>'
        . '</head><body><div class="wrap"><span class="badge">MNB Secure Core v1.0</span><h1>Reusable PHP Security Core Web Demo</h1>'
        . '<p>This page runs through the same framework-free autoloader and applies request size and rate-limit middleware.</p>'
        . '<div class="box"><h2>Escaped XSS sample</h2><p><code>' . $escaped . '</code></p></div>'
        . '<div class="box"><h2>Concepts covered</h2><ol>' . $lis . '</ol></div>'
        . '<p>Run CLI demos with: <code>php demos/run-all-demos.php</code></p></div></body></html>';
    return Response::text($body, 200, ['Content-Type' => 'text/html; charset=UTF-8']);
});

$response = (new SecurityHeaders(['hsts' => false, 'frame_ancestors' => "'self'"]))->apply($response, $nonce->nonce());
$response->send();
