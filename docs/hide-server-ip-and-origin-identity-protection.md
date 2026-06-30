# Hide Server IP and Origin Identity Protection

**Package:** `mnb/mnb-secure-core`  
**Release line:** `MNB Secure Core v1.0.1`  
**Feature area:** Origin Identity Protection and Exposure Hardening Engine

---

## 1. Purpose

The **Hide Server IP and Origin Identity Protection** feature helps reduce the risk of exposing the real application server, backend infrastructure, framework fingerprints, proxy trust mistakes, and unsafe Host/Forwarded header behavior.

This feature is designed to protect against issues such as:

- Direct access to the origin server IP.
- CDN or reverse-proxy bypass.
- Host header poisoning.
- Spoofed `X-Forwarded-*` headers.
- Server/framework fingerprint leakage.
- Internal hostname or private IP exposure.
- Misconfigured trusted proxy handling.
- Unsafe canonical host behavior.
- Origin details leaking through logs or error output.

> Important: a PHP library alone cannot fully hide a server IP. True origin hiding requires CDN/reverse proxy configuration, DNS design, firewall rules, and application-level validation together. This library provides the application controls and readiness checks that support that deployment model.

---

## 2. Main components

The origin protection system is built around these areas:

| Area | Purpose |
|---|---|
| `ServerIdentityHider` | Removes fingerprinting headers from responses. |
| `ServerIdentityProtectionMiddleware` | Blocks direct-IP Host requests and unsafe origin access patterns. |
| `RequestTrustMiddleware` | Trusts forwarded headers only from trusted proxies. |
| `TrustedHostMiddleware` | Blocks unknown or unapproved Host headers. |
| `OriginProtectionPolicy` | Central policy for direct IP, proxy, host, and origin behavior. |
| `OriginExposureScanner` | Produces exposure/readiness findings. |
| `OriginLeakDetector` | Finds private IPs, localhost URLs, and internal hostnames in provided values/content. |
| `ResponseFingerprintAnalyzer` | Detects risky response headers. |
| `FirewallRuleAdvisor` | Generates deployment firewall guidance. |
| `OriginLogRedactor` | Redacts origin/internal infrastructure identifiers from logs. |

---

## 3. Installation

Install the package through Composer:

```bash
composer require mnb/mnb-secure-core
```

Bootstrap normally:

```php
<?php

require __DIR__ . '/vendor/autoload.php';

use Mnb\SecureCore\Core\SecurityKernel;

$config = require __DIR__ . '/config/security.php';
$security = new SecurityKernel($config);
```

---

## 4. Configuration

Add or update the `origin_protection` section in `config/security.php`.

```php
'origin_protection' => [
    'enabled' => true,

    // Application-level origin hardening
    'block_direct_ip_host' => true,
    'block_untrusted_forwarded_headers' => true,
    'require_trusted_proxy' => false,
    'require_cdn_or_proxy_in_production' => true,
    'cdn_or_proxy_enabled' => filter_var($_ENV['CDN_OR_PROXY_ENABLED'] ?? false, FILTER_VALIDATE_BOOL),

    // Public host policy
    'canonical_host' => $_ENV['APP_CANONICAL_HOST'] ?? '',
    'allowed_public_hosts' => array_filter(array_map('trim', explode(',', $_ENV['TRUSTED_HOSTS'] ?? ''))),
    'redirect_to_canonical_host' => false,
    'block_unknown_hosts' => true,

    // Proxy/CDN trust
    'proxy_provider' => $_ENV['ORIGIN_PROXY_PROVIDER'] ?? 'custom',
    'trusted_proxy_headers' => [
        'forwarded',
        'x-forwarded-for',
        'x-forwarded-host',
        'x-forwarded-proto',
        'x-real-ip',
        'cf-connecting-ip',
    ],
    'trusted_proxy_ranges' => array_filter(array_map('trim', explode(',', $_ENV['TRUSTED_PROXIES'] ?? ''))),
    'proxy_ip_allowlist_max_age_days' => 30,

    // Response fingerprint reduction
    'strip_headers' => [
        'Server',
        'X-Powered-By',
        'X-AspNet-Version',
        'X-AspNetMvc-Version',
        'X-Generator',
        'X-Runtime',
        'X-Version',
        'X-Backend-Server',
        'X-Origin-Server',
        'X-Served-By',
    ],

    // Leak detection
    'leak_detection' => [
        'enabled' => true,
        'scan_config' => true,
        'scan_public_files' => false,
        'block_private_ips_in_public_urls' => true,
        'known_origin_hosts' => [],
        'known_origin_ips' => [],
    ],

    // Firewall/deployment advisory
    'firewall' => [
        'enabled' => true,
        'provider' => 'generic',
        'generate_nginx_allow_deny' => true,
        'generate_apache_require_ip' => true,
        'generate_ufw_plan' => true,
    ],

    // Production readiness gate
    'production_gate' => [
        'enabled' => true,
        'block_if_direct_ip_allowed' => true,
        'block_if_no_trusted_hosts' => true,
        'block_if_proxy_required_but_missing' => true,
        'block_if_identity_headers_present' => true,
    ],
],
```

### Production `.env` example

```env
APP_CANONICAL_HOST=example.com
TRUSTED_HOSTS=example.com,www.example.com
CDN_OR_PROXY_ENABLED=true
ORIGIN_PROXY_PROVIDER=cloudflare
TRUSTED_PROXIES=173.245.48.0/20,103.21.244.0/22,103.22.200.0/22
```

Use your actual CDN/reverse-proxy IP ranges. Do not blindly copy sample ranges into production without verifying them.

---

## 5. Recommended middleware order

Origin and host validation should happen early in the HTTP pipeline.

Recommended order:

```text
1. RequestTrustMiddleware
2. TrustedHostMiddleware
3. ServerIdentityProtectionMiddleware
4. SecureRequestMiddleware
5. RateLimitMiddleware
6. Authentication middleware
7. Authorization middleware
8. Application route/controller
9. ErrorHandlingMiddleware wrapper around the pipeline
```

Reason:

- `RequestTrustMiddleware` determines whether forwarded headers are trustworthy.
- `TrustedHostMiddleware` blocks Host header abuse before business logic.
- `ServerIdentityProtectionMiddleware` blocks direct-origin access patterns.
- Response header stripping should happen before the response leaves the app.

---

## 6. Blocking direct IP Host requests

A common origin bypass attempt is to request the server by IP instead of public domain:

```text
http://203.0.113.10/
https://203.0.113.10/
http://[2001:db8::10]/
```

With `block_direct_ip_host` enabled, these requests should be rejected.

Example decision flow:

```php
$policy = $security->originProtectionPolicy();

$decision = $policy->evaluateRequest([
    'host' => '203.0.113.10',
    'remote_addr' => '198.51.100.25',
    'headers' => [],
]);

if (!$decision->allowed()) {
    // Return safe 403/400 response depending on your app style.
    return [
        'status' => false,
        'message' => 'Request blocked by origin protection policy.',
        'reason' => $decision->reason(),
    ];
}
```

Expected blocked reasons may include:

```text
direct_ip_host_blocked
unknown_host_blocked
trusted_proxy_required
untrusted_forwarded_headers
```

---

## 7. Trusted proxy handling

Forwarded headers must be trusted only when the immediate client is a known proxy.

Dangerous headers from public clients:

```http
X-Forwarded-For: 127.0.0.1
X-Forwarded-Host: admin.example.com
X-Forwarded-Proto: https
Forwarded: for=127.0.0.1;host=internal.example.local;proto=https
```

If these headers are accepted from anyone, attackers can spoof:

- client IP,
- original scheme,
- original host,
- trusted proxy identity,
- internal routing assumptions.

Correct behavior:

```text
trusted proxy IP   → forwarded headers may be evaluated
untrusted client   → forwarded headers must be ignored or blocked
```

Example:

```php
$requestTrust = $security->requestTrust();

$clientIp = $requestTrust->clientIp([
    'remote_addr' => '173.245.48.10',
    'headers' => [
        'x-forwarded-for' => '198.51.100.40',
    ],
]);
```

In production, keep `TRUSTED_PROXIES` accurate and up to date.

---

## 8. Trusted hosts and canonical host

Only approved public hostnames should be accepted.

Good:

```text
example.com
www.example.com
```

Bad:

```text
evil.example.net
origin.example.internal
localhost
192.168.1.10
```

Example config:

```env
APP_CANONICAL_HOST=example.com
TRUSTED_HOSTS=example.com,www.example.com
```

Example canonical behavior:

| Incoming Host | Decision |
|---|---|
| `example.com` | allow |
| `www.example.com` | allow or redirect depending on config |
| `203.0.113.10` | block |
| `localhost` | block in production |
| `origin.internal` | block |

If you enable canonical redirects, make sure redirect destinations are generated from configuration, not from user-controlled Host headers.

---

## 9. Response fingerprint reduction

Backend responses often expose server or framework identity.

Risky examples:

```http
Server: Apache/2.4.58 Ubuntu
X-Powered-By: PHP/8.2.12
X-Generator: Laravel
X-Backend-Server: app-node-01
X-Origin-Server: 10.0.1.15
X-Served-By: origin-php-01
```

Use `ServerIdentityHider` to remove those headers:

```php
$headers = [
    'Content-Type' => 'application/json',
    'X-Powered-By' => 'PHP/8.2',
    'X-Origin-Server' => '10.0.1.15',
];

$safeHeaders = $security->serverIdentityHider()->strip($headers);
```

Expected result:

```php
[
    'Content-Type' => 'application/json',
]
```

### Analyze response fingerprints

```php
$report = $security->responseFingerprintAnalyzer()->analyze([
    'Server' => 'Apache/2.4.58 Ubuntu',
    'X-Powered-By' => 'PHP/8.2',
    'X-Backend-Server' => 'app-node-01',
]);

foreach ($report->findings() as $finding) {
    echo $finding['header'] . ': ' . $finding['risk'] . PHP_EOL;
}
```

---

## 10. Origin leak detection

Origin details can leak through:

- config values,
- public assets,
- robots/sitemap output,
- debug pages,
- backup files,
- generated URLs,
- webhook payloads,
- logs,
- error responses,
- source maps,
- email templates.

Examples that should be flagged:

```text
http://192.168.1.10/admin
http://10.0.0.5/internal-api
http://localhost:8080/debug
http://origin.internal/status
http://app-node-01.local
```

Usage:

```php
$detector = $security->originLeakDetector();

$findings = $detector->scanText('API_URL=http://10.0.0.5/internal-api');

foreach ($findings as $finding) {
    echo $finding->type() . ': ' . $finding->safeValue() . PHP_EOL;
}
```

The detector should not print sensitive raw values unless explicitly safe. Use safe summaries in reports.

---

## 11. Firewall rule guidance

Application-level origin blocking is helpful, but firewall-level protection is stronger.

The target production model should be:

```text
Internet users
    ↓
CDN / reverse proxy / load balancer
    ↓
Origin firewall allows only proxy IP ranges
    ↓
Application server
```

The application should not be publicly reachable except through the trusted proxy/CDN.

Generate advisory plan:

```php
$plan = $security->firewallRuleAdvisor()->plan([
    'provider' => 'generic',
    'trusted_proxy_ranges' => [
        '173.245.48.0/20',
        '103.21.244.0/22',
    ],
]);

foreach ($plan->steps() as $step) {
    echo '- ' . $step . PHP_EOL;
}
```

Example generated guidance:

```text
- Allow inbound HTTP/HTTPS only from trusted proxy ranges.
- Deny direct HTTP/HTTPS traffic from all other public IPs.
- Restrict SSH to admin IPs.
- Never expose database/cache/search ports publicly.
- Keep trusted proxy ranges fresh.
```

---

## 12. Origin production gate

Before production release, run the origin gate.

CLI:

```bash
php bin/mnb-secure origin:production-gate
```

The gate should block or warn when:

- origin protection is disabled,
- direct IP Host requests are allowed,
- trusted hosts are missing,
- CDN/proxy is required but not configured,
- trusted proxy ranges are empty,
- risky identity headers are present,
- proxy IP allow-list is stale,
- leak detection finds known origin IPs/hosts.

---

## 13. CLI usage

### Show origin policy

```bash
php bin/mnb-secure origin:policy
```

### Run basic origin check

```bash
php bin/mnb-secure origin:check
```

### Generate exposure report

```bash
php bin/mnb-secure origin:exposure-report
```

### Analyze response fingerprinting

```bash
php bin/mnb-secure origin:fingerprint
```

### Generate firewall plan

```bash
php bin/mnb-secure origin:firewall-plan
```

### Show proxy provider profile

```bash
php bin/mnb-secure origin:proxy-profile cloudflare
```

### Check proxy allow-list freshness

```bash
php bin/mnb-secure origin:proxy-allowlist
```

### Run origin leak scan

```bash
php bin/mnb-secure origin:leak-scan
```

### Run production gate

```bash
php bin/mnb-secure origin:production-gate
```

---

## 14. Example: safe origin middleware flow

```php
use Mnb\SecureCore\Http\Middleware\RequestTrustMiddleware;
use Mnb\SecureCore\Http\Middleware\TrustedHostMiddleware;
use Mnb\SecureCore\Http\Middleware\ServerIdentityProtectionMiddleware;

$request = Request::fromGlobals();

$pipeline = [
    new RequestTrustMiddleware($security->requestTrust()),
    new TrustedHostMiddleware($security->trustedHostPolicy()),
    new ServerIdentityProtectionMiddleware($security->originProtectionPolicy()),
];

foreach ($pipeline as $middleware) {
    $request = $middleware->handle($request);
}

$response = $controller($request);
$response = $security->serverIdentityHider()->protectResponse($response);

return $response;
```

Adapt the exact request/response object to your framework or plain PHP stack.

---

## 15. Example: protected response headers

Recommended response behavior:

```http
Content-Type: application/json
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

Avoid exposing:

```http
Server: Apache/2.4.58 Ubuntu
X-Powered-By: PHP/8.2
X-Origin-Server: 10.0.1.15
X-Backend-Server: app-node-01
```

---

## 16. Logging and redaction

Origin logs should not leak infrastructure identifiers.

Unsafe log:

```json
{
  "origin_ip": "10.0.1.15",
  "backend": "app-node-01.internal",
  "debug_url": "http://localhost:8080/debug"
}
```

Safe log:

```json
{
  "origin_ip": "[redacted-origin-ip]",
  "backend": "[redacted-origin-host]",
  "debug_url": "[redacted-internal-url]"
}
```

Usage:

```php
$redacted = $security->originLogRedactor()->redact([
    'origin_ip' => '10.0.1.15',
    'backend' => 'app-node-01.internal',
]);
```

---

## 17. Integration with safe error handling

Origin details must not appear in public errors.

Unsafe:

```text
Connection failed to http://10.0.1.15/internal-api from /var/www/origin/app.php
```

Safe:

```json
{
  "status": false,
  "message": "Something went wrong. Please try again later.",
  "error": {
    "code": "INTERNAL_ERROR",
    "request_id": "req_..."
  }
}
```

The safe error engine and origin redactor should work together to keep backend details internal and redacted.

---

## 18. Integration with outbound network protection

Origin protection and outbound network protection solve different problems:

| Engine | Protects |
|---|---|
| Origin protection | Who can reach the application and what backend identity is exposed. |
| Outbound network protection | What URLs the server is allowed to call. |

Use both.

Example:

- Origin protection blocks users from hitting `203.0.113.10` directly.
- Outbound network protection blocks the server from calling `http://169.254.169.254` or `http://127.0.0.1`.

---

## 19. Integration with vulnerability matrix

This feature contributes controls for vulnerabilities such as:

| Vulnerability | Expected controls |
|---|---|
| `origin_ip_exposure` | OriginProtectionPolicy, OriginExposureScanner, FirewallRuleAdvisor |
| `server_fingerprint_exposure` | ServerIdentityHider, ResponseFingerprintAnalyzer |
| `host_header_poisoning` | TrustedHostMiddleware, CanonicalHostPolicy |
| `forwarded_header_spoofing` | RequestTrustMiddleware, TrustedProxyPolicy |
| `direct_origin_access` | ServerIdentityProtectionMiddleware, firewall guidance |
| `cdn_bypass` | Proxy allow-list, production gate, firewall plan |
| `private_origin_leakage` | OriginLeakDetector, OriginLogRedactor |

CLI:

```bash
php bin/mnb-secure vulnerabilities:check origin_ip_exposure
php bin/mnb-secure vulnerabilities:check host_header_poisoning
php bin/mnb-secure vulnerabilities:check forwarded_header_spoofing
php bin/mnb-secure vulnerabilities:check server_fingerprint_exposure
```

---

## 20. Testing examples

### Direct IP Host should be blocked

```php
public function testDirectIpHostIsBlocked(): void
{
    $policy = $this->kernel->originProtectionPolicy();

    $decision = $policy->evaluateRequest([
        'host' => '203.0.113.10',
        'remote_addr' => '198.51.100.25',
        'headers' => [],
    ]);

    $this->assertFalse($decision->allowed());
    $this->assertSame('direct_ip_host_blocked', $decision->reason());
}
```

### Trusted public host should pass

```php
public function testTrustedPublicHostPasses(): void
{
    $decision = $this->kernel->originProtectionPolicy()->evaluateRequest([
        'host' => 'example.com',
        'remote_addr' => '198.51.100.25',
        'headers' => [],
    ]);

    $this->assertTrue($decision->allowed());
}
```

### Risky headers should be detected

```php
public function testResponseFingerprintDetected(): void
{
    $report = $this->kernel->responseFingerprintAnalyzer()->analyze([
        'Server' => 'Apache/2.4.58 Ubuntu',
        'X-Powered-By' => 'PHP/8.2',
    ]);

    $this->assertFalse($report->isClean());
    $this->assertGreaterThan(0, count($report->findings()));
}
```

### Private IP leak should be detected

```php
public function testPrivateIpLeakDetected(): void
{
    $findings = $this->kernel->originLeakDetector()
        ->scanText('Internal API: http://10.0.0.5/status');

    $this->assertNotEmpty($findings);
}
```

---

## 21. Production checklist

Before deploying:

```text
[ ] Public DNS points to CDN/proxy, not directly to origin when origin hiding is required.
[ ] Origin firewall allows HTTP/HTTPS only from trusted proxy/CDN ranges.
[ ] `CDN_OR_PROXY_ENABLED=true` is set when proxy/CDN is active.
[ ] `TRUSTED_HOSTS` contains only approved public hostnames.
[ ] `APP_CANONICAL_HOST` is set.
[ ] Direct IP Host requests are blocked.
[ ] Unknown Host requests are blocked.
[ ] Forwarded headers are trusted only from trusted proxies.
[ ] Trusted proxy ranges are current.
[ ] Server/framework/backend headers are stripped.
[ ] Origin leak scan passes.
[ ] Error logs redact internal hosts, IPs, and paths.
[ ] HSTS is enabled only after HTTPS is confirmed.
[ ] Production origin gate passes.
```

---

## 22. Common mistakes

### Mistake: relying only on PHP to hide origin IP

Wrong:

```text
Enable origin middleware only.
Leave firewall open to the world.
DNS points directly to server IP.
```

Correct:

```text
Use CDN/proxy + firewall + trusted hosts + origin middleware.
```

### Mistake: trusting forwarded headers from everyone

Wrong:

```php
$clientIp = $_SERVER['HTTP_X_FORWARDED_FOR'];
```

Correct:

```php
$clientIp = $security->requestTrust()->clientIp($requestContext);
```

### Mistake: allowing any Host header

Wrong:

```text
No trusted host validation.
```

Correct:

```env
TRUSTED_HOSTS=example.com,www.example.com
```

### Mistake: exposing backend identity headers

Wrong:

```http
X-Origin-Server: 10.0.1.15
X-Backend-Server: app-node-01
```

Correct:

```php
$response = $security->serverIdentityHider()->protectResponse($response);
```

### Mistake: logging internal hosts and IPs

Wrong:

```php
$logger->error('Backend failed', ['host' => 'app-node-01.internal']);
```

Correct:

```php
$logger->error('Backend failed', $security->originLogRedactor()->redact([
    'host' => 'app-node-01.internal',
]));
```

---

## 23. Summary

The **Hide Server IP and Origin Identity Protection** feature helps reduce infrastructure exposure by combining:

- direct-IP Host blocking,
- trusted host validation,
- trusted proxy handling,
- forwarded-header spoofing protection,
- response fingerprint reduction,
- origin leak detection,
- origin log redaction,
- firewall guidance,
- production exposure gates.

For real production origin protection, combine this library with correct CDN/reverse-proxy, DNS, TLS, and firewall configuration.

