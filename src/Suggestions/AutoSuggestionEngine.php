<?php
namespace Mnb\SecurityCore\Suggestions;

class AutoSuggestionEngine
{
    /** @var list<array<string,mixed>> */
    private array $rules;

    public function __construct(array $customRules = [])
    {
        $this->rules = array_values(array_merge($this->defaultRules(), $customRules));
    }

    /** @return list<array<string,mixed>> */
    public function suggest(string $typedWordsOrCode, int $limit = 8): array
    {
        $limit = max(1, min(50, $limit));
        $text = strtolower($typedWordsOrCode);
        $tokens = $this->tokens($text);
        $results = [];

        foreach ($this->rules as $rule) {
            $score = $this->scoreRule($rule, $text, $tokens);
            if ($score <= 0) {
                continue;
            }
            $results[] = [
                'id' => $rule['id'],
                'type' => $rule['type'] ?? 'tip',
                'title' => $rule['title'],
                'description' => $rule['description'],
                'confidence' => min(1.0, round($score, 2)),
                'keywords' => $rule['keywords'] ?? [],
                'example' => $rule['example'] ?? null,
            ];
        }

        usort($results, fn(array $a, array $b): int => $b['confidence'] <=> $a['confidence'] ?: strcmp((string)$a['title'], (string)$b['title']));
        return array_slice($results, 0, $limit);
    }

    /** @return list<array<string,mixed>> */
    public function suggestFromCode(string $code, int $limit = 8): array
    {
        $hints = $this->suggest($code, $limit * 2);
        $extra = [];

        if (str_contains($code, 'new SecurityKernel') && !str_contains($code, 'requestTrustMiddleware')) {
            $extra[] = $this->result('missing_request_trust', 'middleware', 'Add request trust middleware before auth/rate limiting.', 'Use $kernel->requestTrustMiddleware() first so forwarded IP/proto/host headers are only trusted from configured proxies.', 0.95, 'Request Trust -> CORS -> Security Headers -> Rate Limit -> Auth');
        }
        if (str_contains($code, 'ApiTokenMiddleware') && !str_contains($code, 'PermissionGuard')) {
            $extra[] = $this->result('missing_permission_guard', 'auth', 'Add scope/permission checks after token validation.', 'ApiTokenMiddleware authenticates the request; PermissionGuard enforces what the authenticated actor may do.', 0.9, 'PermissionGuard::requireScope($request, \'admin:read\');');
        }
        if ((str_contains($code, 'ApiTokenMiddleware') || str_contains($code, 'SessionGuard') || str_contains($code, 'login(')) && !str_contains($code, 'authenticationMiddleware') && !str_contains($code, 'AuthenticationRegistry')) {
            $extra[] = $this->result('missing_authentication_strategy', 'auth', 'Use a named authentication strategy.', 'AuthenticationMiddleware and AuthenticationRegistry centralize bearer, optional bearer, session, signature, admin, and internal-system auth with AuthContext, audits, and safe failures.', 0.92, "\$kernel->authenticationMiddleware('api_bearer')");
        }
        if (preg_match('/storeFromPath\s*\(/', $code) && !str_contains($code, 'uploadPolicy(') && !str_contains($code, 'secureFileManager(')) {
            $extra[] = $this->result('upload_profile_suggestion', 'upload', 'Use an upload security profile for this upload path.', 'Choose images/documents/videos/archives/strict instead of one broad allow-list for every upload.', 0.88, '$manager = $kernel->secureFileManager(profile: \'images\');');
        }
        if ((str_contains($code, '$_POST') || str_contains($code, '->input(') || str_contains($code, 'Request::fromGlobals')) && !str_contains($code, 'inputValidationMiddleware') && !str_contains($code, 'InputValidator')) {
            $extra[] = $this->result('missing_input_validation', 'validation', 'Validate and sanitize request input before controllers.', 'Use InputValidationMiddleware or InputValidator/InputSanitizer to normalize request data and reject invalid submissions before business logic.', 0.9, '$kernel->inputValidationMiddleware([...])');
        }
        if ((str_contains($code, 'PermissionGuard') || str_contains($code, 'TenantGuard') || str_contains($code, 'TrustBoundaryRegistry') || str_contains($code, 'can(') || str_contains($code, 'hasRole(')) && !str_contains($code, 'authorizationMiddleware') && !str_contains($code, 'AuthorizationRegistry')) {
            $extra[] = $this->result('missing_authorization_strategy', 'authorization', 'Use a named authorization policy for resource actions.', 'AuthorizationRegistry unifies roles, scopes, permissions, tenant scope, trust boundaries, field-level read/write filtering, and audit decisions.', 0.94, "\$kernel->authorizationMiddleware('students.update')");
        }
        if ((str_contains($code, 'SecureDatabase') || str_contains($code, 'Response::json') || str_contains($code, 'student') || str_contains($code, 'tenant')) && !str_contains($code, 'trustBoundaryMiddleware') && !str_contains($code, 'TrustBoundaryRegistry')) {
            $extra[] = $this->result('missing_trust_boundary', 'trust_boundary', 'Add trust boundary checks around sensitive resources.', 'Use TrustBoundaryMiddleware or TrustBoundaryRegistry to connect zone, data class, action, tenant, permissions, and audit decisions.', 0.91, "\$kernel->trustBoundaryMiddleware('students.read')");
        }
        if ((str_contains($code, 'Encryption') || str_contains($code, 'DataMasker') || str_contains($code, 'FieldFilter') || str_contains($code, 'fputcsv') || str_contains($code, 'Response::json') || str_contains($code, 'password_hash') || str_contains($code, 'parent_phone')) && !str_contains($code, 'dataProtectionRegistry') && !str_contains($code, 'SafeCsvExporter')) {
            $extra[] = $this->result('missing_data_protection_strategy', 'data_protection', 'Use the data protection strategy for sensitive fields.', 'DataProtectionRegistry centralizes classification, encryption, search hashes, masking, log redaction, safe CSV exports, and encrypted private storage.', 0.93, "\$kernel->dataProtectionRegistry()->protectForResponse('students', \$record, \$request)");
        }
        if ((str_contains($code, 'htmlspecialchars') || str_contains($code, 'header(\'Location') || str_contains($code, 'setcookie(') || str_contains($code, 'echo $') || str_contains($code, 'redirect')) && !str_contains($code, 'webSecurityControls') && !str_contains($code, 'OutputEscaper') && !str_contains($code, 'SafeRedirector')) {
            $extra[] = $this->result('missing_web_security_controls', 'web_security', 'Use web security controls for output, redirects, cookies, cache and signed URLs.', 'WebSecurityControls centralizes output escaping, HTML sanitization, safe redirects, secure cookie defaults, cache-control profiles, and signed URLs for browser/API apps.', 0.92, "\$kernel->webSecurityControls('browser_form')");
        }
        if ((str_contains($code, 'new MiddlewarePipeline') || str_contains($code, 'Request::fromGlobals') || str_contains($code, 'requestTrustMiddleware')) && !str_contains($code, 'secureRequestReceiver') && !str_contains($code, 'requestReceivingPipeline')) {
            $extra[] = $this->result('missing_secure_request_receiver', 'request_receiving', 'Use a named secure request receiving profile.', 'SecureRequestReceiver composes request ID, request trust, host/HTTPS, CORS, method, size, content type, JSON parsing, suspicious detection, validation, rate limit, auth, audit, and trust boundary middleware in a safe order.', 0.93, "\$kernel->secureRequestReceiver('api_authenticated')->handle(\$request, \$controller)");
        }

        return array_slice($this->mergeResults($extra, $hints), 0, max(1, min(50, $limit)));
    }

    /** @return list<string> */
    private function tokens(string $text): array
    {
        preg_match_all('/[a-z0-9_:\\.-]+/i', $text, $matches);
        return array_values(array_unique(array_map('strtolower', $matches[0] ?? [])));
    }

    /** @param array<string,mixed> $rule @param list<string> $tokens */
    private function scoreRule(array $rule, string $text, array $tokens): float
    {
        $keywords = array_map('strtolower', $rule['keywords'] ?? []);
        $score = 0.0;
        foreach ($keywords as $keyword) {
            if ($keyword === '') {
                continue;
            }
            if (in_array($keyword, $tokens, true)) {
                $score += 0.22;
                continue;
            }
            if (str_contains($text, $keyword)) {
                $score += 0.16;
                continue;
            }
            foreach ($tokens as $token) {
                if (strlen($token) >= 3 && str_starts_with($keyword, $token)) {
                    $score += 0.12;
                    break;
                }
            }
        }
        return min(1.0, $score + (float)($rule['base'] ?? 0.0));
    }

    /** @return list<array<string,mixed>> */
    private function defaultRules(): array
    {
        return [
            ['id' => 'auto_audit', 'type' => 'audit', 'title' => 'Enable automatic audit logging for sensitive routes', 'description' => 'AutoAuditMiddleware can record add/edit/delete/submission/email/login/register/password-verification outcomes without storing raw secrets.', 'keywords' => ['audit', 'log', 'login', 'register', 'delete', 'update', 'submission', 'email', 'password'], 'example' => '$kernel->autoAuditMiddleware()'],
            ['id' => 'cors_policy', 'type' => 'cors', 'title' => 'Use strict CORS policy instead of broad wildcard origins', 'description' => 'Configure explicit allowed origins, methods, headers, credentials, exposed headers, and preflight max-age.', 'keywords' => ['cors', 'cross', 'origin', 'preflight', 'access-control', 'credentials'], 'example' => '$kernel->corsMiddleware()'],
            ['id' => 'request_trust', 'type' => 'middleware', 'title' => 'Place request trust middleware first', 'description' => 'Run request trust before rate limiting/auth so client IP, host, and HTTPS status are resolved safely behind proxies/CDNs.', 'keywords' => ['proxy', 'cdn', 'forwarded', 'client ip', 'x-forwarded', 'requesttrust'], 'example' => '$kernel->requestTrustMiddleware()'],
            ['id' => 'security_headers', 'type' => 'headers', 'title' => 'Add security headers middleware near the top of the pipeline', 'description' => 'Use CSP nonces, HSTS, Permissions-Policy, and cross-origin resource policies from the built-in builder.', 'keywords' => ['headers', 'csp', 'nonce', 'hsts', 'permissions-policy', 'coep', 'coop', 'corp'], 'example' => '$kernel->securityHeadersMiddleware()'],
            ['id' => 'rate_policy', 'type' => 'rate_limit', 'title' => 'Use named rate-limit policies for route/user/IP limits', 'description' => 'Named policies make login, API, OTP, and export limits easier to tune and test.', 'keywords' => ['rate', 'limit', 'throttle', 'login', 'otp', 'api'], 'example' => '$kernel->rateLimitMiddleware(\'api\', \'api.profile\')'],
            ['id' => 'auth_context', 'type' => 'auth', 'title' => 'Read AuthContext after API token middleware', 'description' => 'AuthContext gives user id, scopes, permissions, and roles for downstream authorization.', 'keywords' => ['auth', 'token', 'scope', 'permission', 'role', 'bearer'], 'example' => '$auth = $request->attribute(\'auth\');'],
            ['id' => 'upload_profile', 'type' => 'upload', 'title' => 'Choose a specific upload security profile', 'description' => 'Use images/documents/videos/archives/strict profiles instead of one broad upload policy.', 'keywords' => ['upload', 'file', 'image', 'document', 'video', 'archive', 'mime'], 'example' => '$kernel->secureFileManager(profile: \'images\')'],
            ['id' => 'input_validation', 'type' => 'validation', 'title' => 'Validate and sanitize request input before business logic', 'description' => 'Use route-aware request validation for body/query data, field allow-lists, safe sanitization, and 422 responses for invalid submissions.', 'keywords' => ['input', 'validation', 'validate', 'sanitize', 'sanitization', 'request', 'form', 'body', 'query', 'submission'], 'example' => '$kernel->inputValidationMiddleware([...])'],
            ['id' => 'trust_boundary', 'type' => 'trust_boundary', 'title' => 'Enforce trust zones and data boundaries for sensitive resources', 'description' => 'Use named trust boundary policies to connect zone, action, data class, tenant scope, permissions, output filtering, and audit logs.', 'keywords' => ['trust', 'zone', 'boundary', 'data class', 'tenant', 'resource', 'sensitive', 'classification'], 'example' => "\$kernel->trustBoundaryMiddleware('students.read')"],
            ['id' => 'secure_request_receiving', 'type' => 'request_receiving', 'title' => 'Use SecureRequestReceiver as the application front door', 'description' => 'Named receiving profiles compose request trust, CORS, method/content-type checks, body parsing, suspicious detection, input validation, rate limits, auth, audit, and trust boundaries in a safe order.', 'keywords' => ['request', 'receiving', 'receiver', 'front door', 'method', 'content-type', 'json', 'webhook', 'pipeline'], 'example' => "\$kernel->secureRequestReceiver('api_authenticated')"],
            ['id' => 'authentication_strategy', 'type' => 'auth', 'title' => 'Use named authentication strategies for routes', 'description' => 'Authentication strategies centralize bearer tokens, optional bearer, sessions, webhook signatures, admin auth, scopes, roles, permissions, audits, and safe failure responses.', 'keywords' => ['authentication', 'auth strategy', 'bearer', 'session', 'webhook', 'password', 'login', 'register', 'credential'], 'example' => "\$kernel->authenticationMiddleware('api_bearer')"],
            ['id' => 'authorization_strategy', 'type' => 'authorization', 'title' => 'Use named authorization policies for protected resources', 'description' => 'Authorization policies unify roles, scopes, permissions, tenant matching, trust boundaries, field-level read/write filtering, and auditable decisions.', 'keywords' => ['authorization', 'authorize', 'permission', 'role', 'scope', 'rbac', 'tenant', 'policy', 'field', 'access'], 'example' => "\$kernel->authorizationMiddleware('students.update')"],
            ['id' => 'data_protection_strategy', 'type' => 'data_protection', 'title' => 'Use data protection policies for sensitive fields and exports', 'description' => 'DataProtectionRegistry unifies field classification, encryption, searchable hashes, masking, log redaction, CSV injection-safe exports, and encrypted private storage.', 'keywords' => ['data', 'protection', 'encryption', 'masking', 'classification', 'csv', 'export', 'redact', 'field', 'phone', 'email', 'sensitive'], 'example' => "\$kernel->dataProtectionRegistry()->protectForStorage('students', \$data)"],
            ['id' => 'web_security_controls', 'type' => 'web_security', 'title' => 'Use web security controls for browser output and redirects', 'description' => 'Web security controls provide escaping, HTML sanitization, safe redirects, secure cookies, cache-control profiles, and signed URLs.', 'keywords' => ['web', 'xss', 'escape', 'html', 'sanitize', 'redirect', 'cookie', 'cache-control', 'signed url'], 'example' => "\$kernel->webSecurityControls('browser_page')"],
            ['id' => 'doctor', 'type' => 'cli', 'title' => 'Run doctor before pushing or deploying', 'description' => 'Doctor checks PHP extensions, config, storage paths, headers, upload scanner, secrets, and package readiness.', 'keywords' => ['doctor', 'deploy', 'production', 'check', 'ci', 'release'], 'example' => 'php bin/mnb-secure doctor'],
        ];
    }

    /** @param list<array<string,mixed>> $first @param list<array<string,mixed>> $second @return list<array<string,mixed>> */
    private function mergeResults(array $first, array $second): array
    {
        $seen = [];
        $merged = [];
        foreach (array_merge($first, $second) as $result) {
            $id = (string)($result['id'] ?? '');
            if ($id === '' || isset($seen[$id])) {
                continue;
            }
            $seen[$id] = true;
            $merged[] = $result;
        }
        usort($merged, fn(array $a, array $b): int => ($b['confidence'] ?? 0) <=> ($a['confidence'] ?? 0));
        return $merged;
    }

    /** @return array<string,mixed> */
    private function result(string $id, string $type, string $title, string $description, float $confidence, ?string $example = null): array
    {
        return compact('id', 'type', 'title', 'description', 'confidence', 'example');
    }
}
