# Web Application Security Controls

**Package:** `mnb/mnb-secure-core`  
**Release line:** `MNB Secure Core v1.0.1`  
**Document type:** Detailed feature documentation and code usage  
**Feature area:** Security headers, CSP, HSTS, CSRF, CORS, secure cookies, output escaping, HTML sanitization, safe redirects, cache-control, signed URLs, XSS enforcement, safe templates, and browser-facing hardening

---

## 1. Overview

The **Web Application Security Controls** layer protects browser-facing routes and API responses from common web attacks.

It focuses on what happens after a request is accepted and before a response is returned:

```text
Incoming browser/API request
    ↓
Request receiving and validation
    ↓
Authentication / authorization
    ↓
Web security controls
    ↓
Safe response with headers, cookies, redirects, encoded output, and cache policy
```

This feature area helps protect against:

```text
Cross-site scripting / XSS
Missing security headers
CSRF on browser form routes
Open redirects
Unsafe cookies
Clickjacking
MIME sniffing
Weak referrer leakage
Unsafe inline scripts/styles
Sensitive page caching
Unsafe user-generated HTML
Unsigned temporary URLs
Over-permissive CORS
Raw template echo mistakes
```

`mnb-secure-core` provides a set of reusable controls rather than forcing one framework. You can use them in plain PHP, Slim, Laravel-style middleware pipelines, custom routers, or internal admin panels.

---

## 2. Main Classes

The web security layer is mainly built around these classes:

```text
Mnb\SecurityCore\Http\SecurityHeaders
Mnb\SecurityCore\Http\SecurityHeadersBuilder
Mnb\SecurityCore\Http\Middleware\SecurityHeadersMiddleware
Mnb\SecurityCore\Http\Middleware\CsrfMiddleware
Mnb\SecurityCore\Http\Middleware\CorsMiddleware
Mnb\SecurityCore\Http\Middleware\CacheControlMiddleware
Mnb\SecurityCore\Auth\Csrf

Mnb\SecurityCore\Security\CspNonceManager

Mnb\SecurityCore\Web\WebSecurityRegistry
Mnb\SecurityCore\Web\WebSecurityProfile
Mnb\SecurityCore\Web\WebSecurityControls
Mnb\SecurityCore\Web\OutputEscaper
Mnb\SecurityCore\Web\OutputEncodingPolicy
Mnb\SecurityCore\Web\TemplateSafeValue
Mnb\SecurityCore\Web\SafeViewData
Mnb\SecurityCore\Web\SafeTemplateRenderer
Mnb\SecurityCore\Web\UnsafeOutputScanner
Mnb\SecurityCore\Web\XssEnforcementReport
Mnb\SecurityCore\Web\HtmlSanitizer
Mnb\SecurityCore\Web\SafeRedirector
Mnb\SecurityCore\Web\SecureCookieBuilder
Mnb\SecurityCore\Web\CacheControlPolicy
Mnb\SecurityCore\Web\SignedUrl
```

Core access normally goes through:

```php
use Mnb\SecurityCore\Core\SecurityKernel;

$config = require __DIR__ . '/config/security.php';
$kernel = new SecurityKernel($config);
```

---

## 3. Installation

Install the package from Packagist:

```bash
composer require mnb/mnb-secure-core
```

Bootstrap Composer autoloading:

```php
require __DIR__ . '/vendor/autoload.php';

use Mnb\SecurityCore\Core\SecurityKernel;

$config = require __DIR__ . '/config/security.php';
$kernel = new SecurityKernel($config);
```

When installed through Composer, package files live under:

```text
vendor/mnb/mnb-secure-core
```

---

## 4. What This Feature Controls

The Web Application Security Controls feature includes these protection groups:

| Area | Purpose |
|---|---|
| Security headers | Add CSP, HSTS, frame, MIME, referrer, permissions, and cross-origin isolation headers. |
| CSP nonces | Support nonce-based script/style execution. |
| CSRF | Protect browser form/state-changing routes. |
| CORS | Restrict cross-origin API access. |
| Secure cookies | Generate cookies with `Secure`, `HttpOnly`, `SameSite`, and safe names/values. |
| Output escaping | Escape values for HTML, attributes, JavaScript, CSS, and URL contexts. |
| HTML sanitization | Allow limited user-generated HTML while removing scripts and dangerous attributes. |
| Safe redirects | Block external or untrusted redirect targets. |
| Cache control | Prevent sensitive pages/API responses from being cached. |
| Signed URLs | Generate temporary HMAC-signed links. |
| Safe templates | Render small templates using encoded/safe values. |
| Unsafe output scanning | Detect raw PHP echo patterns and unsafe output usage. |

---

## 5. Recommended Configuration

The related configuration normally lives in:

```text
config/security.php
config/security.production.php
```

A practical web security configuration looks like this:

```php
return [
    'security_headers' => [
        'enabled' => true,

        'hsts' => [
            'enabled' => false, // enable only after HTTPS is fully working
            'max_age' => 31536000,
            'include_subdomains' => true,
            'preload' => false,
            'only_on_https' => true,
        ],

        'csp' => [
            'enabled' => true,
            'report_only' => false,
            'nonce_enabled' => true,
            'auto_nonce' => false,
            'nonce_directives' => ['script-src', 'style-src'],
            'directives' => [
                'default-src' => ["'self'"],
                'script-src' => ["'self'"],
                'style-src' => ["'self'"],
                'img-src' => ["'self'", 'data:'],
                'font-src' => ["'self'", 'data:'],
                'connect-src' => ["'self'"],
                'object-src' => ["'none'"],
                'base-uri' => ["'self'"],
                'form-action' => ["'self'"],
                'frame-ancestors' => ["'self'"],
            ],
        ],

        'content_type_options' => 'nosniff',
        'referrer_policy' => 'strict-origin-when-cross-origin',
        'x_frame_options' => 'SAMEORIGIN',
        'permissions_policy' => [
            'preset' => 'strict',
        ],
        'cross_origin_opener_policy' => 'same-origin',
        'cross_origin_resource_policy' => 'same-origin',
        'cross_origin_embedder_policy' => null,
    ],

    'cors' => [
        'enabled' => true,
        'allowed_origins' => ['https://app.example.com'],
        'allowed_origin_patterns' => [],
        'allowed_methods' => ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
        'allowed_headers' => ['Content-Type', 'Authorization', 'X-CSRF-Token', 'X-Requested-With'],
        'exposed_headers' => ['X-Request-ID'],
        'allow_credentials' => false,
        'allow_null_origin' => false,
        'allow_private_network' => false,
        'max_age' => 600,
    ],

    'web_security' => [
        'enabled' => true,

        'output_encoding' => [
            'enabled' => true,
            'enforce_by_default' => true,
            'require_safe_values' => true,
            'fail_on_raw_echo_patterns' => true,
            'allowed_raw_variables' => [],
        ],

        'profiles' => [
            'browser_page' => [
                'security_headers' => true,
                'cache_policy' => 'private_user',
                'csrf' => false,
                'output_escape' => true,
            ],
            'browser_form' => [
                'security_headers' => true,
                'cache_policy' => 'sensitive_no_store',
                'csrf' => true,
                'input_validation' => true,
                'safe_redirects' => true,
                'output_escape' => true,
            ],
            'admin_panel' => [
                'security_headers' => true,
                'cache_policy' => 'sensitive_no_store',
                'csrf' => true,
                'auth_strategy' => 'admin_bearer',
                'authorization' => true,
                'frame_policy' => 'deny',
            ],
            'json_api' => [
                'security_headers' => true,
                'cors' => true,
                'cache_policy' => 'no_store',
                'input_validation' => true,
                'auth_strategy' => 'api_bearer',
                'authorization' => true,
            ],
        ],

        'redirects' => [
            'allow_external' => false,
            'allowed_hosts' => [],
        ],

        'cookies' => [
            'secure' => true,
            'http_only' => true,
            'same_site' => 'Lax',
            'path' => '/',
        ],

        'html_sanitizer' => [
            'allowed_tags' => ['p', 'br', 'strong', 'em', 'ul', 'ol', 'li', 'a'],
            'allowed_attributes' => ['href', 'title'],
            'allow_data_images' => false,
        ],

        'signed_urls' => [
            'key' => $_ENV['SIGNED_URL_KEY'] ?? '',
            'default_ttl' => 900,
        ],
    ],
];
```

For production, keep `HSTS_ENABLED=false` until the site is fully HTTPS-ready. After HTTPS is verified, enable HSTS.

---

## 6. Security Headers

Security headers reduce browser-side attack surface.

Recommended headers include:

```text
Content-Security-Policy
Strict-Transport-Security
X-Content-Type-Options
X-Frame-Options
Referrer-Policy
Permissions-Policy
Cross-Origin-Opener-Policy
Cross-Origin-Resource-Policy
```

### Build headers manually

```php
$headers = $kernel->securityHeadersMiddleware();
```

Most applications use the middleware instead of manually constructing headers.

### Middleware usage

```php
use Mnb\SecurityCore\Http\MiddlewarePipeline;

$pipeline = new MiddlewarePipeline([
    $kernel->requestIdMiddleware(),
    $kernel->errorHandlingMiddleware(),
    $kernel->securityHeadersMiddleware(),
]);

$response = $pipeline->handle($request, $controller);
```

### Recommended placement

Security headers should be near the outer response layer:

```text
RequestIdMiddleware
ErrorHandlingMiddleware
ServerIdentityProtectionMiddleware
TrustedHostMiddleware
HttpsMiddleware
RequestTrustMiddleware
SecurityHeadersMiddleware
CorsMiddleware
RequestSizeMiddleware
JsonBodyParserMiddleware
InputValidationMiddleware
RateLimitMiddleware
AuthenticationMiddleware
AuthorizationMiddleware
Controller
```

`SecurityHeadersMiddleware` should run early enough to apply headers to normal responses and error responses.

---

## 7. Content Security Policy / CSP

CSP helps reduce XSS impact by limiting where scripts, styles, images, fonts, frames, and connections may load from.

Example strict baseline:

```php
'csp' => [
    'enabled' => true,
    'directives' => [
        'default-src' => ["'self'"],
        'script-src' => ["'self'"],
        'style-src' => ["'self'"],
        'img-src' => ["'self'", 'data:'],
        'object-src' => ["'none'"],
        'base-uri' => ["'self'"],
        'form-action' => ["'self'"],
        'frame-ancestors' => ["'self'"],
    ],
]
```

### CSP nonce usage

For inline scripts/styles that must exist, use a nonce instead of allowing all inline scripts.

```php
use Mnb\SecurityCore\Security\CspNonceManager;

$nonce = new CspNonceManager();

echo '<script ' . $nonce->scriptAttribute() . '>console.log("safe inline script");</script>';
```

Then apply the same nonce to security headers:

```php
$middleware = $kernel->securityHeadersMiddleware(
    nonceResolver: fn () => $nonce->value()
);
```

Generated script tag:

```html
<script nonce="...">console.log("safe inline script");</script>
```

Important rules:

```text
Do not use unsafe-inline in production unless absolutely required.
Prefer nonce-based inline scripts.
Avoid dynamic script URLs from user input.
Keep object-src 'none'.
Keep base-uri 'self'.
Keep form-action restricted.
```

---

## 8. HSTS / HTTPS Hardening

HSTS tells browsers to use HTTPS automatically after the first successful secure visit.

Production-ready config:

```php
'hsts' => [
    'enabled' => true,
    'max_age' => 31536000,
    'include_subdomains' => true,
    'preload' => false,
    'only_on_https' => true,
],
```

Use HSTS only when:

```text
HTTPS works for the main domain.
HTTPS works for subdomains if include_subdomains is true.
You are not relying on plain HTTP for any route.
You understand preload requirements before setting preload=true.
```

Recommended rollout:

```text
1. Deploy HTTPS.
2. Test all public routes.
3. Enable HSTS with small max-age.
4. Increase max-age.
5. Add includeSubDomains only when subdomains are ready.
6. Add preload only when fully ready.
```

---

## 9. CSRF Protection

CSRF protects browser-based state-changing requests.

Use CSRF for:

```text
HTML login forms
Profile update forms
Admin settings forms
Password change forms
Delete buttons
Payment initiation forms
Any cookie-authenticated POST/PUT/PATCH/DELETE route
```

Usually do not use CSRF for:

```text
Bearer-token API routes
Webhook routes using HMAC signatures
Internal service calls using trusted auth
```

### Generate a token

```php
$csrf = new Mnb\SecurityCore\Auth\Csrf();
$token = $csrf->token();
```

Render in a form:

```php
echo '<input type="hidden" name="_csrf" value="' . htmlspecialchars($token, ENT_QUOTES, 'UTF-8') . '">';
```

### Verify manually

```php
if (!$csrf->verify($_POST['_csrf'] ?? '')) {
    http_response_code(419);
    echo 'CSRF token invalid.';
    exit;
}
```

### Middleware usage

```php
$pipeline = new MiddlewarePipeline([
    $kernel->requestIdMiddleware(),
    $kernel->errorHandlingMiddleware(),
    $kernel->securityHeadersMiddleware(),
    new Mnb\SecurityCore\Http\Middleware\CsrfMiddleware($csrf),
]);
```

For route profiles, set browser form routes to `csrf => true` and webhook/API routes to `csrf => false` when they use another authentication strategy.

---

## 10. CORS Controls

CORS controls which browser origins can call your API.

Safe production approach:

```php
'cors' => [
    'enabled' => true,
    'allowed_origins' => ['https://app.example.com'],
    'allowed_methods' => ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    'allowed_headers' => ['Content-Type', 'Authorization', 'X-CSRF-Token'],
    'allow_credentials' => false,
    'allow_null_origin' => false,
    'allow_private_network' => false,
]
```

Avoid this in production:

```php
'allowed_origins' => ['*'];
'allow_credentials' => true;
```

That combination is dangerous and should not be used for sensitive authenticated APIs.

Middleware usage:

```php
$pipeline = new MiddlewarePipeline([
    $kernel->securityHeadersMiddleware(),
    $kernel->corsMiddleware(),
]);
```

CORS should not replace authentication or authorization. It is a browser access control, not a server-side identity check.

---

## 11. Secure Cookies

Use `SecureCookieBuilder` to generate safe `Set-Cookie` values.

```php
$cookie = $kernel->secureCookieBuilder()->make('mnb_session', $sessionId, [
    'max_age' => 3600,
    'same_site' => 'Lax',
]);

header('Set-Cookie: ' . $cookie, false);
```

Recommended cookie defaults:

```text
Secure=true in production
HttpOnly=true for session cookies
SameSite=Lax for normal app sessions
SameSite=Strict for highly sensitive admin routes when practical
SameSite=None only when Secure=true and cross-site usage is required
Path=/ unless narrowed intentionally
```

Never put sensitive raw values in cookies:

```text
password
raw API token
raw refresh token
private PII
authorization secret
```

Prefer opaque session IDs or signed/encrypted token references.

---

## 12. Output Escaping

Output escaping is the main defense against reflected and stored XSS in templates.

Use the right escaping method for the output context.

```php
$escaper = $kernel->outputEscaper();

$html = $escaper->html($user->name);
$attr = $escaper->attr($buttonTitle);
$url  = $escaper->url($nextUrl);
$js   = $escaper->js($message);
$css  = $escaper->css($colorName);
```

### HTML body context

```php
<p><?= $kernel->outputEscaper()->html($comment) ?></p>
```

### Attribute context

```php
<input value="<?= $kernel->outputEscaper()->attr($value) ?>">
```

### URL context

```php
<a href="<?= $kernel->outputEscaper()->url($url) ?>">Open</a>
```

### JavaScript string context

```php
<script>
    const message = "<?= $kernel->outputEscaper()->js($message) ?>";
</script>
```

### CSS context

```php
<div style="color: <?= $kernel->outputEscaper()->css($color) ?>">
    Safe styled text
</div>
```

Do not use one escaping function for every context. HTML escaping is not the same as JavaScript escaping or URL escaping.

---

## 13. Safe View Data

`SafeViewData` helps prepare encoded values before passing them to templates.

```php
$view = $kernel->safeViewData()
    ->html('title', $pageTitle)
    ->html('username', $userName)
    ->attr('inputValue', $oldInput)
    ->url('profileUrl', '/users/' . $userId);

$data = $view->strings();
```

Usage in template:

```php
<h1><?= $data['title'] ?></h1>
<p><?= $data['username'] ?></p>
<input value="<?= $data['inputValue'] ?>">
<a href="<?= $data['profileUrl'] ?>">Profile</a>
```

This pattern reduces accidental raw output.

---

## 14. Safe Template Renderer

For small templates, use `SafeTemplateRenderer`.

```php
$renderer = $kernel->safeTemplateRenderer();

echo $renderer->renderString(
    '<h1>{{ title }}</h1><a href="{{ url|url }}">Open</a>',
    [
        'title' => '<script>alert(1)</script>Hello',
        'url' => '/dashboard?tab=<main>',
    ]
);
```

The renderer supports encoded placeholders:

```text
{{ name }}       HTML context by default
{{ href|url }}   URL context
{{ value|attr }} Attribute context
{{ body|html }}  HTML context
{{ script|js }}  JavaScript string context
{{ css|css }}    CSS context
```

For full framework integration, continue using your framework renderer, but pass only already-escaped values or use the framework’s native escaping mode.

---

## 15. Unsafe Output Scanner

Upgrade 36 introduced XSS enforcement helpers. The scanner helps detect dangerous raw echo patterns.

```php
$scanner = $kernel->unsafeOutputScanner();

$findings = $scanner->scanString(
    '<?php echo $userInput; ?>',
    'resources/views/profile.php'
);

if ($findings !== []) {
    print_r($findings);
}
```

Scan multiple files:

```php
$findings = $kernel->unsafeOutputScanner()->scanFiles([
    __DIR__ . '/resources/views/profile.php',
    __DIR__ . '/resources/views/admin.php',
]);
```

CLI helper:

```bash
php bin/mnb-secure xss:scan
```

The scanner is not a replacement for code review, but it catches common unsafe patterns like:

```php
<?= $userInput ?>
<?php echo $_GET['name']; ?>
```

---

## 16. HTML Sanitization

Escaping and sanitization are different.

Use escaping when you want to show text exactly as text:

```php
echo $kernel->outputEscaper()->html($comment);
```

Use sanitization only when you intentionally allow limited HTML:

```php
$sanitized = $kernel->htmlSanitizer()->sanitize($userBioHtml);
echo $sanitized;
```

Example input:

```html
<p>Hello <strong>world</strong></p><script>alert(1)</script>
```

Expected safe output:

```html
<p>Hello <strong>world</strong></p>
```

Recommended allowed tags:

```text
p
br
strong
em
ul
ol
li
a
```

Avoid allowing:

```text
script
iframe
object
embed
form
input
style
svg
math
```

Be very careful with attributes such as:

```text
onload
onclick
style
srcdoc
href="javascript:..."
```

---

## 17. Safe Redirects

Open redirects are common in login/logout flows.

Unsafe example:

```php
header('Location: ' . $_GET['next']);
```

Safe usage:

```php
$target = $kernel->safeRedirector('app.example.com')->to(
    $_GET['next'] ?? '/',
    '/dashboard'
);

header('Location: ' . $target);
exit;
```

Default behavior:

```text
Relative app paths are allowed.
External URLs are blocked unless explicitly allowed.
Invalid/empty redirects fall back safely.
```

Example:

```php
$redirector = $kernel->safeRedirector('app.example.com', [
    'allow_external' => false,
]);

$redirector->to('/dashboard', '/');
// /dashboard

$redirector->to('https://evil.example/phish', '/');
// /
```

If external redirects are needed, allow only trusted hosts:

```php
$redirector = $kernel->safeRedirector('app.example.com', [
    'allow_external' => true,
    'allowed_hosts' => ['billing.example.com'],
]);
```

---

## 18. Cache-Control Policies

Sensitive responses should not be cached by browsers, proxies, or shared caches.

Use `CacheControlPolicy` or middleware.

```php
$headers = $kernel->cacheControlPolicy()->headers('sensitive_no_store');

foreach ($headers as $name => $value) {
    header($name . ': ' . $value);
}
```

Middleware usage:

```php
$pipeline = new MiddlewarePipeline([
    $kernel->cacheControlMiddleware('sensitive_no_store'),
]);
```

Recommended profiles:

```text
public_static        Static assets that can be cached
private_user         User-specific pages
sensitive_no_store   Login, account, admin, payment, tokens
no_store             APIs with sensitive data
```

Use `sensitive_no_store` for:

```text
login page
OTP screen
password reset screen
user profile
admin dashboard
payment page
download token page
```

---

## 19. Signed URLs

Signed URLs protect temporary links such as downloads, email actions, exports, and private resources.

Create a signed URL:

```php
$signed = $kernel->signedUrl()->sign(
    '/downloads/report.csv',
    ['file_id' => 'file_123'],
    time() + 900,
    'download'
);
```

Verify the signed URL:

```php
if (!$kernel->signedUrl()->verify($signed, 'download')) {
    http_response_code(403);
    echo 'Invalid or expired link.';
    exit;
}
```

Recommended rules:

```text
Use short TTLs.
Use different purposes for different link types.
Do not include secrets in URL parameters.
Do not sign unsafe absolute paths.
Prefer file IDs over filesystem paths.
```

Example purposes:

```text
download
email_verify
password_reset
export_download
private_document
```

---

## 20. Web Security Profiles

Profiles make it easier to apply different controls to different route types.

```php
$registry = $kernel->webSecurityRegistry();

$pageProfile = $registry->get('browser_page');
$formProfile = $registry->get('browser_form');
$apiProfile  = $registry->get('json_api');
```

Check profile options:

```php
if ($formProfile->enabled('csrf')) {
    // Apply CSRF middleware or manual verification.
}
```

Get controls for a profile:

```php
$controls = $kernel->webSecurityControls('browser_form');

$safeTitle = $controls->escapeHtml($title);
$cleanBio = $controls->sanitizeHtml($bioHtml);
$redirect = $controls->safeRedirect($_GET['next'] ?? null, '/dashboard');
```

Recommended profile mapping:

| Route type | Profile |
|---|---|
| Public page | `browser_page` |
| Login/register/contact form | `browser_form` |
| Admin dashboard | `admin_panel` |
| JSON API | `json_api` |
| File upload route | `upload_endpoint` |

---

## 21. Full Browser Form Example

```php
use Mnb\SecurityCore\Core\SecurityKernel;
use Mnb\SecurityCore\Auth\Csrf;

require __DIR__ . '/vendor/autoload.php';

$config = require __DIR__ . '/config/security.php';
$kernel = new SecurityKernel($config);

$csrf = new Csrf();
$esc = $kernel->outputEscaper();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!$csrf->verify($_POST['_csrf'] ?? '')) {
        http_response_code(419);
        echo 'Invalid CSRF token.';
        exit;
    }

    $name = trim((string)($_POST['name'] ?? ''));

    // Continue with validation, authz, persistence, etc.
}

$token = $csrf->token();
?>
<!doctype html>
<html>
<head>
    <title>Safe Form</title>
</head>
<body>
    <form method="post">
        <input type="hidden" name="_csrf" value="<?= $esc->attr($token) ?>">
        <label>Name</label>
        <input name="name" value="<?= $esc->attr($_POST['name'] ?? '') ?>">
        <button type="submit">Save</button>
    </form>
</body>
</html>
```

In a real app, also apply:

```text
SecurityHeadersMiddleware
CacheControlMiddleware
RequestSizeMiddleware
InputValidationMiddleware
RateLimitMiddleware
AuthenticationMiddleware when needed
AuthorizationMiddleware when needed
```

---

## 22. Full API Route Example

```php
$pipeline = new MiddlewarePipeline([
    $kernel->requestIdMiddleware(),
    $kernel->errorHandlingMiddleware(),
    $kernel->serverIdentityProtectionMiddleware(),
    $kernel->trustedHostMiddleware(),
    $kernel->httpsMiddleware(),
    $kernel->securityHeadersMiddleware(),
    $kernel->corsMiddleware(),
    $kernel->requestSizeMiddleware(),
    $kernel->jsonBodyParserMiddleware(),
    $kernel->inputValidationMiddleware(),
    $kernel->rateLimitMiddleware(),
    $kernel->authenticationMiddleware('api_bearer'),
    $kernel->authorizationMiddleware('api.default'),
]);

$response = $pipeline->handle($request, function ($request) use ($kernel) {
    return $kernel->safeResponseBuilder()->json([
        'status' => true,
        'message' => 'OK',
    ]);
});
```

For APIs:

```text
Prefer bearer tokens or API tokens.
Usually disable CSRF.
Use CORS allow-list.
Set Cache-Control: no-store for sensitive API responses.
Return JSON only.
Do not expose stack traces or raw validation internals.
```

---

## 23. Admin Panel Example

Admin panel routes should use stricter browser controls.

Recommended profile:

```php
'admin_panel' => [
    'security_headers' => true,
    'cache_policy' => 'sensitive_no_store',
    'csrf' => true,
    'auth_strategy' => 'admin_bearer',
    'authorization' => true,
    'frame_policy' => 'deny',
]
```

Recommended middleware:

```php
$pipeline = new MiddlewarePipeline([
    $kernel->requestIdMiddleware(),
    $kernel->errorHandlingMiddleware(),
    $kernel->securityHeadersMiddleware(),
    $kernel->cacheControlMiddleware('sensitive_no_store'),
    $kernel->rateLimitMiddleware(),
    $kernel->authenticationMiddleware('admin_bearer'),
    $kernel->authorizationMiddleware('admin_panel'),
]);
```

Admin pages should avoid:

```text
public caching
external iframing
unsafe-inline scripts
unescaped database values
raw HTML from admin-entered content
unrestricted redirects
```

---

## 24. CLI Commands

Useful CLI commands for this feature area:

```bash
php bin/mnb-secure config:validate
php bin/mnb-secure doctor
php bin/mnb-secure production:readiness
php bin/mnb-secure final:gate

php bin/mnb-secure xss:policy
php bin/mnb-secure xss:scan
php bin/mnb-secure xss:escape-sample
```

Related request/security commands:

```bash
php bin/mnb-secure origin:check
php bin/mnb-secure origin:fingerprint
php bin/mnb-secure vulnerabilities:report
php bin/mnb-secure vulnerabilities:check xss
php bin/mnb-secure vulnerabilities:check csrf
```

---

## 25. Testing Examples

### Test output escaping

```php
$esc = $kernel->outputEscaper();

$unsafe = '<script>alert(1)</script>';
$safe = $esc->html($unsafe);

assert($safe === '&lt;script&gt;alert(1)&lt;/script&gt;');
```

### Test safe redirects

```php
$redirector = $kernel->safeRedirector('app.example.com', [
    'allow_external' => false,
]);

assert($redirector->to('/dashboard', '/') === '/dashboard');
assert($redirector->to('https://evil.example', '/') === '/');
```

### Test signed URL verification

```php
$signed = $kernel->signedUrl()->sign('/download', ['id' => '123'], time() + 300, 'download');

assert($kernel->signedUrl()->verify($signed, 'download') === true);
assert($kernel->signedUrl()->verify($signed, 'different-purpose') === false);
```

### Test HTML sanitizer

```php
$html = '<p>Hello</p><script>alert(1)</script>';
$clean = $kernel->htmlSanitizer()->sanitize($html);

assert(str_contains($clean, '<script>') === false);
assert(str_contains($clean, '<p>Hello</p>') === true);
```

### Test unsafe output scanner

```php
$findings = $kernel->unsafeOutputScanner()->scanString(
    '<?= $userInput ?>',
    'profile.php'
);

assert(count($findings) > 0);
```

---

## 26. Production Checklist

Before production, verify:

```text
Security headers enabled.
CSP enabled.
CSP does not allow broad unsafe-inline unless explicitly justified.
HSTS enabled only after HTTPS is ready.
X-Content-Type-Options nosniff enabled.
Frame protection enabled.
Referrer policy configured.
Permissions-Policy configured.
CORS allows only trusted origins.
CORS credentials are not used with wildcard origins.
CSRF enabled for cookie-authenticated browser forms.
CSRF disabled only for routes protected by bearer/HMAC/internal auth.
Cookies use Secure, HttpOnly, SameSite.
Sensitive pages use no-store cache policy.
Safe redirects are used for all user-controlled redirect targets.
Signed URLs use a strong SIGNED_URL_KEY.
User-generated HTML is sanitized or escaped.
Templates use context-aware escaping.
Unsafe output scanner is part of CI/release review.
Origin fingerprint headers are stripped.
Safe error responses are enabled.
```

Run:

```bash
php bin/mnb-secure config:validate
php bin/mnb-secure production:readiness
php bin/mnb-secure xss:scan
php bin/mnb-secure final:gate
```

---

## 27. Common Mistakes

### Mistake: using HTML escaping inside JavaScript

Bad:

```php
<script>
const name = "<?= htmlspecialchars($name) ?>";
</script>
```

Good:

```php
<script>
const name = "<?= $kernel->outputEscaper()->js($name) ?>";
</script>
```

### Mistake: sanitizing when escaping is enough

Bad:

```php
echo $kernel->htmlSanitizer()->sanitize($plainTextComment);
```

Good:

```php
echo $kernel->outputEscaper()->html($plainTextComment);
```

Use sanitization only when limited HTML is intentionally allowed.

### Mistake: trusting redirect URLs from query strings

Bad:

```php
header('Location: ' . $_GET['next']);
```

Good:

```php
header('Location: ' . $kernel->safeRedirector()->to($_GET['next'] ?? null, '/'));
```

### Mistake: enabling HSTS before HTTPS is ready

HSTS can lock users into HTTPS. Enable it only after HTTPS is stable for all affected domains.

### Mistake: using wildcard CORS for authenticated APIs

Bad:

```php
'allowed_origins' => ['*'],
'allow_credentials' => true,
```

Good:

```php
'allowed_origins' => ['https://app.example.com'],
'allow_credentials' => false,
```

### Mistake: storing raw sensitive data in cookies

Bad:

```text
user_email=john@example.com
api_token=secret-token
```

Good:

```text
mnb_session=opaque_random_session_id
```

---

## 28. Relationship With Other Engines

Web Application Security Controls work with these other `mnb-secure-core` areas:

| Engine | Relationship |
|---|---|
| Secure Request Receiving | Validates request method, content type, size, body, and auth profile before web controls execute. |
| Authentication Strategy | Protects browser/API identity. |
| Authorization Strategy | Ensures users can access only allowed resources. |
| Data Protection Strategy | Masks/encrypts sensitive values before output. |
| Safe Error Response Engine | Prevents stack traces and technical errors in browser/API responses. |
| Origin Identity Protection | Strips server identity headers and blocks invalid hosts/direct IP access. |
| Token/Session Control | Controls session cookies, revocation, and remember-me workflows. |
| Production Readiness Patch | Adds XSS scanning, final gates, and release checks. |

Recommended route lifecycle:

```text
Request trust and origin checks
    ↓
Secure request receiving
    ↓
Rate limit / throughput / memory guard
    ↓
Authentication
    ↓
Authorization
    ↓
Business logic
    ↓
Data protection
    ↓
Output escaping / sanitization
    ↓
Security headers / cache control / cookies
    ↓
Safe response
```

---

## 29. Demo File

Related demo files:

```text
demos/06-web-application-security-controls.php
demos/16-error-handling-custom-errors-logs-hidden-frontend.php
demos/34-safe-error-response-technical-log-isolation-engine.php
demos/40-final-production-readiness-xss-release-consolidation-patch.php
```

Run all demos:

```bash
php demos/run-all-demos.php
```

Run tests:

```bash
php tests/run-tests.php
```

---

## 30. Summary

The **Web Application Security Controls** feature provides browser/API response hardening for production PHP applications.

It gives you:

```text
Security headers
CSP and nonce support
HSTS readiness
CSRF protection
CORS control
Secure cookie generation
Context-aware output escaping
Safe view data helpers
Safe template rendering
HTML sanitization
Safe redirects
Cache-control policies
Signed URLs
Unsafe output scanning
Production XSS readiness support
```

The safest default is simple:

```text
Validate input.
Authenticate and authorize.
Escape all output by context.
Sanitize only intentionally allowed HTML.
Use secure cookies.
Use safe redirects.
Use no-store for sensitive pages.
Use strict security headers.
Run XSS scan before release.
```
