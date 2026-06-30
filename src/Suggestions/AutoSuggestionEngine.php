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
        if (preg_match('/storeFromPath\s*\(/', $code) && !str_contains($code, 'uploadPolicy(') && !str_contains($code, 'secureFileManager(')) {
            $extra[] = $this->result('upload_profile_suggestion', 'upload', 'Use an upload security profile for this upload path.', 'Choose images/documents/videos/archives/strict instead of one broad allow-list for every upload.', 0.88, '$manager = $kernel->secureFileManager(profile: \'images\');');
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
