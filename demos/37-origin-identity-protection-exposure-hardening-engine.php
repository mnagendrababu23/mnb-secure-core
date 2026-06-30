<?php
require __DIR__ . '/../autoload.php';

use Mnb\SecurityCore\Core\SecurityKernel;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;
use Mnb\SecurityCore\Http\Middleware\ServerIdentityProtectionMiddleware;
use Mnb\SecurityCore\Http\MiddlewarePipeline;
use Mnb\SecurityCore\Origin\CanonicalHostPolicy;
use Mnb\SecurityCore\Origin\OriginLeakDetector;
use Mnb\SecurityCore\Origin\ResponseFingerprintAnalyzer;

function pass(string $message): void { echo "[PASS] {$message}\n"; }
function fail(string $message): void { echo "[FAIL] {$message}\n"; exit(1); }

$config = [
    'app' => [
        'env' => 'production',
        'trusted_hosts' => ['app.example.com'],
        'trusted_proxies' => ['203.0.113.0/24'],
    ],
    'origin_protection' => [
        'enabled' => true,
        'block_direct_ip_host' => true,
        'block_untrusted_forwarded_headers' => true,
        'require_trusted_proxy' => false,
        'cdn_or_proxy_enabled' => true,
        'canonical_host' => 'app.example.com',
        'allowed_public_hosts' => ['app.example.com', 'www.app.example.com'],
        'redirect_to_canonical_host' => true,
        'block_unknown_hosts' => true,
        'proxy_provider' => 'cloudflare',
        'trusted_proxy_ranges' => ['203.0.113.0/24'],
        'proxy_ip_allowlist_updated_at' => date('Y-m-d'),
        'strip_headers' => ['Server', 'X-Powered-By', 'X-Backend-Server', 'X-Origin-Server', 'X-Served-By'],
        'leak_detection' => ['enabled' => true, 'known_origin_hosts' => ['origin.internal'], 'known_origin_ips' => ['192.168.1.10']],
        'firewall' => ['enabled' => true],
    ],
];

$kernel = new SecurityKernel($config);
$policy = $kernel->originProtectionPolicy();
pass('Origin protection policy loaded');

$ipRequest = new Request('GET', '/', [], [], ['host' => '203.0.113.10'], ['HTTP_HOST' => '203.0.113.10', 'REMOTE_ADDR' => '198.51.100.10']);
$ipDecision = $policy->evaluateRequest($ipRequest);
$ipDecision->allowed() ? fail('Direct IP Host should be blocked') : pass('Direct IP Host request blocked');

$safeRequest = new Request('GET', '/', [], [], ['host' => 'app.example.com'], ['HTTP_HOST' => 'app.example.com', 'REMOTE_ADDR' => '198.51.100.10']);
$policy->evaluateRequest($safeRequest)->allowed() ? pass('Safe public host request allowed') : fail('Safe public host should be allowed');

$spoofed = new Request('GET', '/', [], [], ['host' => 'app.example.com', 'x-forwarded-host' => 'admin.example.com'], ['HTTP_HOST' => 'app.example.com', 'REMOTE_ADDR' => '198.51.100.10']);
$policy->evaluateRequest($spoofed)->allowed() ? fail('Spoofed forwarded headers should be blocked') : pass('Spoofed forwarded headers blocked');

$trusted = new Request('GET', '/', [], [], ['host' => 'origin.internal', 'x-forwarded-host' => 'app.example.com'], ['HTTP_HOST' => 'origin.internal', 'REMOTE_ADDR' => '203.0.113.5'], ['203.0.113.0/24']);
$policy->evaluateRequest($trusted)->allowed() ? pass('Trusted proxy forwarded host accepted') : fail('Trusted proxy request should be allowed');

$pipeline = new MiddlewarePipeline([new ServerIdentityProtectionMiddleware($config['origin_protection'])]);
$response = $pipeline->handle($safeRequest, fn() => Response::text('ok', 200, ['Server' => 'Apache', 'X-Powered-By' => 'PHP', 'X-Backend-Server' => 'app-01']));
(!isset($response->headers()['Server']) && !isset($response->headers()['X-Powered-By']) && !isset($response->headers()['X-Backend-Server'])) ? pass('Identity headers stripped from response') : fail('Identity headers were not stripped');

$fingerprint = ResponseFingerprintAnalyzer::fromConfig($config)->analyze(['Server' => 'Apache/2.4', 'X-Powered-By' => 'PHP/8.2'])->toArray();
(!$fingerprint['passed'] && count($fingerprint['findings']) >= 2) ? pass('Response fingerprint report generated') : fail('Fingerprint report should contain findings');

$canonical = CanonicalHostPolicy::fromConfig($config)->evaluate('www.app.example.com');
$canonical->action() === 'redirect' ? pass('Canonical host decision generated') : fail('Canonical host redirect should be generated');

$leaks = OriginLeakDetector::fromConfig($config)->reportForString('http://192.168.1.10/private http://origin.internal/hook');
(!$leaks['passed'] && $leaks['count'] >= 2) ? pass('Origin leak detector finds private IP and internal host URLs') : fail('Origin leak detector should find leaks');

$firewall = $kernel->firewallRuleAdvisor()->plan()->toArray();
count($firewall['rules']) >= 3 ? pass('Firewall plan generated') : fail('Firewall plan should contain deployment controls');

$gate = $kernel->originExposureScanner()->scan()->toArray();
$gate['passed'] ? pass('Production gate passes safe origin config') : fail('Safe origin config should pass production gate');

$matrix = $kernel->vulnerabilityAdvisor()->recommend('origin_ip_exposure');
($matrix && ($matrix['status'] ?? '') === 'protected') ? pass('Vulnerability matrix coverage improved') : fail('Origin vulnerability matrix coverage missing');

echo "Origin Identity Protection and Exposure Hardening Engine demo completed.\n";
