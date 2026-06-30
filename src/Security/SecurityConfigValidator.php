<?php
namespace Mnb\SecurityCore\Security;

use Mnb\SecurityCore\Core\StorageDriverResolver;
use Mnb\SecurityCore\Database\SqlIdentifier;
use Throwable;

class SecurityConfigValidator
{
    /** @var array<int,array<string,mixed>> */
    private array $issues = [];

    public function __construct(private array $config) {}

    public static function validateConfig(array $config): array
    {
        return (new self($config))->validate();
    }

    /** @return array{passed:bool,issues:array<int,array<string,mixed>>,errors:array<int,array<string,mixed>>,warnings:array<int,array<string,mixed>>} */
    public function validate(): array
    {
        $this->issues = [];

        $this->validateApp();
        $this->validateCookies();
        $this->validatePaths();
        $this->validateLimits();
        $this->validateUploads();
        $this->validateStores();
        $this->validateRedis();
        $this->validateCors();
        $this->validateSecurityHeaders();
        $this->validateOriginProtection();
        $this->validateErrors();
        $this->validateMemory();
        $this->validateDatabase();
        $this->validateThroughput();
        $this->validatePentest();

        $errors = array_values(array_filter($this->issues, fn(array $issue): bool => in_array($issue['level'], ['critical', 'high'], true)));
        $warnings = array_values(array_filter($this->issues, fn(array $issue): bool => !in_array($issue['level'], ['critical', 'high'], true)));

        return [
            'passed' => count($errors) === 0,
            'issues' => $this->issues,
            'errors' => $errors,
            'warnings' => $warnings,
        ];
    }

    private function validateApp(): void
    {
        $app = $this->section('app', true);
        if ($app === null) {
            return;
        }

        $env = $app['env'] ?? 'local';
        if (!$this->isStringLike($env)) {
            $this->issue('high', 'invalid_app_env', 'app.env', 'APP_ENV must be a string.', 'string', $env);
        } elseif (!in_array((string)$env, ['local', 'development', 'dev', 'testing', 'test', 'staging', 'production'], true)) {
            $this->issue('medium', 'unknown_app_env', 'app.env', 'APP_ENV should be one of local, development, testing, staging, or production.', 'known environment name', $env);
        }

        $this->bool($app, 'debug', 'app.debug');
        $this->bool($app, 'force_https', 'app.force_https');

        if (isset($app['url']) && !$this->isStringLike($app['url'])) {
            $this->issue('medium', 'invalid_app_url_type', 'app.url', 'APP_URL should be a string URL.', 'string', $app['url']);
        } elseif (!empty($app['url']) && !$this->looksLikeUrl((string)$app['url'])) {
            $this->issue('medium', 'invalid_app_url', 'app.url', 'APP_URL should include a valid http or https scheme and host.', 'http(s) URL', $app['url']);
        }

        $appKey = (string)($app['key'] ?? '');
        if ($appKey === '') {
            $this->issue($this->isProduction($app) ? 'critical' : 'medium', 'missing_app_key', 'app.key', 'APP_KEY is missing. Generate a 32+ byte secret before using encryption or production mode.', '32+ character secret', '');
        } elseif (strlen($appKey) < 32) {
            $this->issue($this->isProduction($app) ? 'critical' : 'medium', 'weak_app_key', 'app.key', 'APP_KEY should be at least 32 characters.', '>=32 chars', strlen($appKey) . ' chars');
        }

        $trustedHosts = $app['trusted_hosts'] ?? [];
        if (!$this->stringList($trustedHosts, 'app.trusted_hosts')) {
            return;
        }
        foreach ($trustedHosts as $host) {
            $host = (string)$host;
            if ($host === '*') {
                $this->issue($this->isProduction($app) ? 'high' : 'medium', 'wildcard_trusted_host', 'app.trusted_hosts', 'Wildcard trusted host should not be used for public deployments.', 'explicit hostnames', '*');
            }
            if (str_contains($host, '://')) {
                $this->issue('medium', 'trusted_host_contains_scheme', 'app.trusted_hosts', 'Trusted hosts should contain hostnames only, not URL schemes.', 'example.com', $host);
            }
        }

        $trustedProxies = $app['trusted_proxies'] ?? [];
        if ($this->stringList($trustedProxies, 'app.trusted_proxies', false)) {
            foreach ($trustedProxies as $proxy) {
                $proxy = (string)$proxy;
                if ($proxy === '*') {
                    $this->issue($this->isProduction($app) ? 'high' : 'medium', 'wildcard_trusted_proxy', 'app.trusted_proxies', 'Wildcard trusted proxy trusts forwarded headers from every client. Use explicit CDN/proxy IPs or CIDR ranges.', 'proxy IP/CIDR list', '*');
                    continue;
                }
                if (!$this->isIpOrCidr($proxy)) {
                    $this->issue('high', 'invalid_trusted_proxy', 'app.trusted_proxies', 'Trusted proxy entries must be IP addresses or CIDR ranges.', 'IP or CIDR', $proxy);
                }
            }
        }
    }

    private function validateCookies(): void
    {
        $cookies = $this->section('cookies', true);
        if ($cookies === null) {
            return;
        }

        $this->bool($cookies, 'secure', 'cookies.secure');
        $this->bool($cookies, 'http_only', 'cookies.http_only');

        $sameSite = $cookies['same_site'] ?? 'Lax';
        if (!$this->isStringLike($sameSite) || !in_array(strtolower((string)$sameSite), ['lax', 'strict', 'none'], true)) {
            $this->issue('high', 'invalid_same_site_cookie', 'cookies.same_site', 'SESSION_SAME_SITE must be Lax, Strict, or None.', 'Lax|Strict|None', $sameSite);
        }
        if (strtolower((string)$sameSite) === 'none' && empty($cookies['secure'])) {
            $this->issue('high', 'same_site_none_without_secure', 'cookies', 'SameSite=None cookies must also use the Secure flag.', 'secure=true', ['same_site' => $sameSite, 'secure' => $cookies['secure'] ?? null]);
        }
    }

    private function validatePaths(): void
    {
        $paths = $this->section('paths', true);
        if ($paths === null) {
            return;
        }

        foreach (['private_storage', 'quarantine', 'cache', 'logs', 'audit', 'backups', 'tokens'] as $key) {
            if (!array_key_exists($key, $paths)) {
                $this->issue('medium', 'missing_path_' . $key, 'paths.' . $key, "Path '{$key}' is not configured.", 'non-empty path string', null);
                continue;
            }
            if (!$this->isStringLike($paths[$key]) || trim((string)$paths[$key]) === '') {
                $this->issue('high', 'invalid_path_' . $key, 'paths.' . $key, "Path '{$key}' must be a non-empty string.", 'non-empty path string', $paths[$key]);
            }
        }
    }

    private function validateLimits(): void
    {
        $limits = $this->section('limits', true);
        if ($limits === null) {
            return;
        }

        $this->positiveInt($limits, 'request_max_bytes', 'limits.request_max_bytes');
        $this->positiveInt($limits, 'upload_max_bytes', 'limits.upload_max_bytes');
        if (isset($limits['request_max_bytes'], $limits['upload_max_bytes']) && (int)$limits['request_max_bytes'] < (int)$limits['upload_max_bytes']) {
            $this->issue('medium', 'request_limit_smaller_than_upload_limit', 'limits', 'request_max_bytes is smaller than upload_max_bytes; uploads may be rejected before upload validation runs.', 'request_max_bytes >= upload_max_bytes', ['request_max_bytes' => $limits['request_max_bytes'], 'upload_max_bytes' => $limits['upload_max_bytes']]);
        }

        foreach (['login', 'api', 'otp', 'export'] as $policy) {
            if (!isset($limits[$policy])) {
                $this->issue('medium', 'missing_rate_policy_' . $policy, 'limits.' . $policy, "Rate limit policy '{$policy}' is not configured.", ['max' => 'positive int', 'seconds' => 'positive int'], null);
                continue;
            }
            if (!is_array($limits[$policy])) {
                $this->issue('high', 'invalid_rate_policy_' . $policy, 'limits.' . $policy, "Rate limit policy '{$policy}' must be an array.", ['max' => 'positive int', 'seconds' => 'positive int'], $limits[$policy]);
                continue;
            }
            $this->positiveInt($limits[$policy], 'max', 'limits.' . $policy . '.max');
            $this->positiveInt($limits[$policy], 'seconds', 'limits.' . $policy . '.seconds');
            $this->rateLimitKeyBy($limits[$policy], $policy);
        }

        foreach ($limits as $name => $policyConfig) {
            if (!is_string($name) || in_array($name, ['request_max_bytes', 'upload_max_bytes'], true) || in_array($name, ['login', 'api', 'otp', 'export'], true)) {
                continue;
            }
            if (!is_array($policyConfig) || (!array_key_exists('max', $policyConfig) && !array_key_exists('max_attempts', $policyConfig))) {
                continue;
            }
            if (!preg_match('/^[a-z0-9][a-z0-9_.:-]{0,80}$/', strtolower($name))) {
                $this->issue('high', 'invalid_rate_policy_name_' . preg_replace('/[^a-z0-9_]+/i', '_', $name), 'limits.' . $name, 'Rate limit policy names must use safe identifier characters.', 'letters, numbers, dash, underscore, dot or colon', $name);
            }
            $this->positiveInt($policyConfig, 'max', 'limits.' . $name . '.max');
            if (!isset($policyConfig['seconds']) && !isset($policyConfig['decay_seconds']) && !isset($policyConfig['decay'])) {
                $this->issue('high', 'missing_rate_policy_seconds_' . $name, 'limits.' . $name, "Rate limit policy '{$name}' must define seconds or decay_seconds.", 'positive int', null);
            }
            $this->rateLimitKeyBy($policyConfig, $name);
        }
    }

    /** @param array<string,mixed> $policy */
    private function rateLimitKeyBy(array $policy, string $name): void
    {
        $keyBy = $policy['key_by'] ?? $policy['by'] ?? null;
        if ($keyBy === null) {
            return;
        }
        if (is_string($keyBy)) {
            $keyBy = array_filter(array_map('trim', explode(',', $keyBy)));
        }
        if (!is_array($keyBy) || $keyBy === []) {
            $this->issue('medium', 'invalid_rate_policy_key_by_' . $name, 'limits.' . $name . '.key_by', 'Rate limit policy key_by must be a non-empty array or comma-separated string.', ['ip', 'user', 'route', 'path', 'method', 'auth'], $keyBy);
            return;
        }

        $allowed = ['ip', 'user', 'route', 'path', 'method', 'auth'];
        foreach ($keyBy as $part) {
            $part = strtolower(trim((string)$part));
            if ($part === '' || !in_array($part, $allowed, true)) {
                $this->issue('medium', 'unsupported_rate_policy_key_part_' . $name, 'limits.' . $name . '.key_by', "Unsupported rate limit key part '{$part}' for policy '{$name}'.", $allowed, $keyBy);
                return;
            }
        }
    }

    private function validateUploads(): void
    {
        $uploads = $this->section('uploads', true);
        if ($uploads === null) {
            return;
        }

        foreach (['allowed_extensions', 'allowed_mime_prefixes', 'blocked_extensions'] as $key) {
            $this->stringList($uploads[$key] ?? [], 'uploads.' . $key, $key !== 'blocked_extensions');
        }

        $dangerous = ['php', 'phtml', 'phar', 'cgi', 'pl', 'sh', 'exe', 'com', 'bat', 'cmd', 'js', 'html', 'htm', 'svg'];
        $allowedExtensions = array_map(fn($ext): string => strtolower(ltrim((string)$ext, '.')), is_array($uploads['allowed_extensions'] ?? null) ? $uploads['allowed_extensions'] : []);
        $dangerousAllowed = array_values(array_intersect($allowedExtensions, $dangerous));
        if ($dangerousAllowed !== []) {
            $this->issue('critical', 'dangerous_upload_extension_allowed', 'uploads.allowed_extensions', 'Executable or scriptable upload extensions must not be allowed.', 'safe document/image extensions only', $dangerousAllowed);
        }

        foreach ($allowedExtensions as $ext) {
            if ($ext === '' || !preg_match('/^[a-z0-9][a-z0-9_+-]*$/i', $ext)) {
                $this->issue('medium', 'invalid_upload_extension', 'uploads.allowed_extensions', 'Upload extensions should be plain extension names without dots, paths, or wildcards.', 'jpg', $ext);
            }
        }

        $this->bool($uploads, 'deny_double_extensions', 'uploads.deny_double_extensions');
        $this->bool($uploads, 'randomize_names', 'uploads.randomize_names');
        $this->bool($uploads, 'reject_executable_content', 'uploads.reject_executable_content');
        $this->positiveInt($uploads, 'max_original_name_length', 'uploads.max_original_name_length', required: false);

        $scanner = $uploads['scanner'] ?? [];
        if (!is_array($scanner)) {
            $this->issue('high', 'invalid_upload_scanner_config', 'uploads.scanner', 'Upload scanner config must be an array.', 'array', $scanner);
            return;
        }

        $driver = $scanner['driver'] ?? 'heuristic';
        if (!$this->isStringLike($driver) || !in_array((string)$driver, ['none', 'heuristic', 'clamav', 'composite'], true)) {
            $this->issue('high', 'invalid_upload_scanner_driver', 'uploads.scanner.driver', 'Upload scanner driver must be none, heuristic, clamav, or composite.', 'none|heuristic|clamav|composite', $driver);
        }
        $this->positiveInt($scanner, 'timeout_seconds', 'uploads.scanner.timeout_seconds', required: false);
        $this->positiveInt($scanner, 'heuristic_read_bytes', 'uploads.scanner.heuristic_read_bytes', required: false);
        $this->bool($scanner, 'fail_closed', 'uploads.scanner.fail_closed', required: false);
        if (in_array((string)$driver, ['clamav', 'composite'], true) && empty($scanner['clamav_binary'])) {
            $this->issue('medium', 'missing_clamav_binary', 'uploads.scanner.clamav_binary', 'ClamAV/composite scanner should configure the clamscan binary path/name.', 'clamscan path/name', $scanner['clamav_binary'] ?? null);
        }
    }

    private function validateStores(): void
    {
        $paths = is_array($this->config['paths'] ?? null) ? $this->config['paths'] : [];
        $database = is_array($this->config['database'] ?? null) ? $this->config['database'] : [];
        $databaseDriver = strtolower((string)($database['driver'] ?? 'mysql'));

        foreach (['cache', 'rate_limiter', 'token_store'] as $sectionName) {
            $section = $this->section($sectionName, true);
            if ($section === null) {
                continue;
            }

            $driver = $section['driver'] ?? 'file';
            $normalizedDriver = is_scalar($driver) ? strtolower(trim((string)$driver)) : null;
            if (!$this->isStringLike($driver) || !in_array((string)$normalizedDriver, StorageDriverResolver::supportedDrivers(), true)) {
                $this->issue('high', 'invalid_' . $sectionName . '_driver', $sectionName . '.driver', "{$sectionName} driver must be file, redis, or database.", 'file|redis|database', $driver);
                continue;
            }

            if (isset($section['prefix']) && !$this->isStringLike($section['prefix'])) {
                $this->issue('medium', 'invalid_' . $sectionName . '_prefix', $sectionName . '.prefix', "{$sectionName} prefix should be a string.", 'string', $section['prefix']);
            }

            if (isset($section['prefix']) && is_scalar($section['prefix']) && (string)$section['prefix'] === '') {
                $this->issue('low', 'empty_' . $sectionName . '_prefix', $sectionName . '.prefix', "{$sectionName} prefix is empty. This is allowed, but distinct prefixes help avoid key collisions across apps.", 'non-empty prefix recommended', '');
            }

            if (isset($section['table'])) {
                $this->sqlIdentifier($section['table'], $sectionName . '.table', $sectionName . ' table');
            }

            if ($normalizedDriver === StorageDriverResolver::FILE) {
                $this->validateFileStorePath($sectionName, $paths);
            }

            if ($normalizedDriver === StorageDriverResolver::REDIS) {
                if (!class_exists('Redis')) {
                    $this->issue('medium', 'redis_extension_missing_for_' . $sectionName, $sectionName . '.driver', "{$sectionName} uses redis driver, but ext-redis is not installed. Inject a compatible Redis client manually or install ext-redis.", 'ext-redis or injected Redis-compatible client', 'ext-redis missing');
                }
                if (!is_array($this->config['redis'] ?? null)) {
                    $this->issue('high', 'missing_redis_config_for_' . $sectionName, 'redis', "{$sectionName} uses redis driver, but redis config section is missing.", 'redis config array', null);
                }
            }

            if ($normalizedDriver === StorageDriverResolver::DATABASE) {
                if (!isset($section['table']) || !$this->isStringLike($section['table']) || trim((string)$section['table']) === '') {
                    $this->issue('medium', 'missing_' . $sectionName . '_table', $sectionName . '.table', "{$sectionName} uses database driver, so a table name should be configured explicitly.", 'safe SQL table identifier', $section['table'] ?? null);
                }
                if ($databaseDriver !== 'mysql') {
                    $this->issue('high', 'unsupported_database_store_driver_for_' . $sectionName, 'database.driver', "Database-backed {$sectionName} storage currently requires MySQL/MariaDB because the bundled store uses MySQL-compatible upsert and locking semantics.", 'mysql', $databaseDriver ?: null);
                }
            }
        }
    }

    private function validateFileStorePath(string $sectionName, array $paths): void
    {
        if ($sectionName === 'cache') {
            $path = $paths['cache'] ?? null;
            $pathName = 'paths.cache';
        } elseif ($sectionName === 'rate_limiter') {
            $path = $paths['cache'] ?? null;
            $pathName = 'paths.cache';
        } else {
            $path = $paths['tokens'] ?? null;
            $pathName = 'paths.tokens';
        }

        if (!$this->isStringLike($path) || trim((string)$path) === '') {
            $this->issue('high', 'missing_file_store_path_for_' . $sectionName, $pathName, "{$sectionName} uses file driver, but its storage path is missing or empty.", 'non-empty path string', $path);
        }
    }

    private function validateRedis(): void
    {
        $redis = $this->section('redis', false);
        if ($redis === null) {
            return;
        }
        if (isset($redis['host']) && !$this->isStringLike($redis['host'])) {
            $this->issue('medium', 'invalid_redis_host', 'redis.host', 'Redis host should be a string.', 'string', $redis['host']);
        }
        $this->intRange($redis, 'port', 'redis.port', 1, 65535, required: false);
        $this->positiveNumber($redis, 'timeout', 'redis.timeout', required: false);
        if (isset($redis['database'])) {
            $this->intRange($redis, 'database', 'redis.database', 0, 15, required: false);
        }
    }

    private function validateCors(): void
    {
        $cors = $this->section('cors', false);
        if ($cors === null) {
            return;
        }
        $this->stringList($cors['allowed_origins'] ?? [], 'cors.allowed_origins', true);
        $this->stringList($cors['allowed_methods'] ?? [], 'cors.allowed_methods', true);
        $this->stringList($cors['allowed_headers'] ?? [], 'cors.allowed_headers', true);
        if (in_array('*', $cors['allowed_origins'] ?? [], true) && $this->isProduction($this->config['app'] ?? [])) {
            $this->issue('medium', 'wildcard_cors_origin', 'cors.allowed_origins', 'Wildcard CORS origins should be avoided in production APIs.', 'explicit origins', '*');
        }
    }

    private function validateSecurityHeaders(): void
    {
        $headers = $this->section('security_headers', false);
        if ($headers === null) {
            return;
        }
        $this->bool($headers, 'hsts', 'security_headers.hsts', required: false);
        foreach (['frame_ancestors', 'content_type_options', 'referrer_policy'] as $key) {
            if (isset($headers[$key]) && !$this->isStringLike($headers[$key])) {
                $this->issue('medium', 'invalid_security_header_' . $key, 'security_headers.' . $key, "security_headers.{$key} should be a string.", 'string', $headers[$key]);
            }
        }
    }

    private function validateOriginProtection(): void
    {
        $origin = $this->section('origin_protection', false);
        if ($origin === null) {
            return;
        }

        foreach ([
            'enabled',
            'block_direct_ip_host',
            'cdn_or_proxy_enabled',
            'require_cdn_or_proxy_in_production',
            'hide_php_session_cookie_name',
            'block_untrusted_forwarded_headers',
            'require_trusted_proxy',
            'emit_headers',
        ] as $key) {
            $this->bool($origin, $key, 'origin_protection.' . $key, required: false);
        }

        if (isset($origin['strip_headers'])) {
            $this->stringList($origin['strip_headers'], 'origin_protection.strip_headers', false);
        }

        $app = is_array($this->config['app'] ?? null) ? $this->config['app'] : [];
        $trustedProxies = is_array($app['trusted_proxies'] ?? null) ? array_filter($app['trusted_proxies']) : [];

        if (!empty($origin['cdn_or_proxy_enabled']) && $trustedProxies === []) {
            $this->issue('medium', 'cdn_enabled_without_trusted_proxies', 'app.trusted_proxies', 'CDN/proxy mode is marked enabled, but no trusted proxy IP/CIDR ranges are configured. Forwarded headers will not be trusted.', 'trusted proxy IP/CIDR list', []);
        }

        if (!empty($origin['require_trusted_proxy']) && $trustedProxies === []) {
            $this->issue('high', 'require_trusted_proxy_without_proxies', 'origin_protection.require_trusted_proxy', 'require_trusted_proxy blocks all direct requests unless app.trusted_proxies contains the proxy/CDN IP ranges.', 'configured app.trusted_proxies', []);
        }

        if ($this->isProduction($app) && array_key_exists('block_untrusted_forwarded_headers', $origin) && empty($origin['block_untrusted_forwarded_headers'])) {
            $this->issue('medium', 'untrusted_forwarded_headers_allowed', 'origin_protection.block_untrusted_forwarded_headers', 'Production apps should reject spoofed Forwarded/X-Forwarded-* headers from untrusted clients.', 'true', false);
        }
    }

    private function validateErrors(): void
    {
        $errors = $this->section('errors', true);
        if ($errors === null) {
            return;
        }
        $this->bool($errors, 'hide_frontend_errors', 'errors.hide_frontend_errors', required: false);
        $format = $errors['response_format'] ?? 'auto';
        if (!$this->isStringLike($format) || !in_array((string)$format, ['auto', 'json', 'html', 'text'], true)) {
            $this->issue('high', 'invalid_error_response_format', 'errors.response_format', 'Error response format must be auto, json, html, or text.', 'auto|json|html|text', $format);
        }
    }

    private function validateMemory(): void
    {
        $memory = $this->section('memory', false);
        if ($memory === null) {
            return;
        }
        $this->numberRange($memory, 'warning_ratio', 'memory.warning_ratio', 0.01, 0.99, required: false);
        $this->numberRange($memory, 'critical_ratio', 'memory.critical_ratio', 0.01, 1.0, required: false);
        if (isset($memory['warning_ratio'], $memory['critical_ratio']) && (float)$memory['warning_ratio'] >= (float)$memory['critical_ratio']) {
            $this->issue('high', 'invalid_memory_ratio_order', 'memory', 'memory.warning_ratio must be lower than memory.critical_ratio.', 'warning < critical', ['warning_ratio' => $memory['warning_ratio'], 'critical_ratio' => $memory['critical_ratio']]);
        }
        foreach (['default_chunk_size', 'min_chunk_size', 'max_chunk_size'] as $key) {
            $this->positiveInt($memory, $key, 'memory.' . $key, required: false);
        }
        if (isset($memory['min_chunk_size'], $memory['max_chunk_size']) && (int)$memory['max_chunk_size'] < (int)$memory['min_chunk_size']) {
            $this->issue('high', 'invalid_memory_chunk_range', 'memory', 'memory.max_chunk_size must be greater than or equal to memory.min_chunk_size.', 'max >= min', ['min_chunk_size' => $memory['min_chunk_size'], 'max_chunk_size' => $memory['max_chunk_size']]);
        }
    }

    private function validateDatabase(): void
    {
        $database = $this->section('database', false);
        if ($database === null) {
            return;
        }
        $driver = $database['driver'] ?? 'mysql';
        if (!$this->isStringLike($driver) || !in_array((string)$driver, ['mysql', 'sqlite', 'pgsql'], true)) {
            $this->issue('high', 'invalid_database_driver', 'database.driver', 'Database driver should be mysql, sqlite, or pgsql.', 'mysql|sqlite|pgsql', $driver);
        }
        if (isset($database['port'])) {
            $this->intRange($database, 'port', 'database.port', 1, 65535, required: false);
        }
        foreach (['host', 'database', 'username', 'charset', 'dsn'] as $key) {
            if (isset($database[$key]) && !$this->isStringLike($database[$key])) {
                $this->issue('medium', 'invalid_database_' . $key, 'database.' . $key, "database.{$key} should be a string.", 'string', $database[$key]);
            }
        }
        if (isset($database['require_policies'])) {
            $this->bool($database, 'require_policies', 'database.require_policies', required: false);
        }
        if (isset($database['soft_delete_default'])) {
            $this->bool($database, 'soft_delete_default', 'database.soft_delete_default', required: false);
        }
    }

    private function validateThroughput(): void
    {
        $throughput = $this->section('throughput', false);
        if ($throughput === null) {
            return;
        }
        $this->positiveNumber($throughput, 'target_rps', 'throughput.target_rps', required: false);
        foreach (['warning_latency_ms', 'critical_latency_ms', 'max_concurrency', 'queue_warning_depth', 'sample_window_seconds'] as $key) {
            $this->positiveInt($throughput, $key, 'throughput.' . $key, required: false);
        }
        if (isset($throughput['warning_latency_ms'], $throughput['critical_latency_ms']) && (int)$throughput['warning_latency_ms'] > (int)$throughput['critical_latency_ms']) {
            $this->issue('high', 'invalid_throughput_latency_order', 'throughput', 'throughput.warning_latency_ms should be lower than or equal to throughput.critical_latency_ms.', 'warning <= critical', ['warning_latency_ms' => $throughput['warning_latency_ms'], 'critical_latency_ms' => $throughput['critical_latency_ms']]);
        }
        $this->bool($throughput, 'emit_headers', 'throughput.emit_headers', required: false);
        $this->bool($throughput, 'block_critical_latency', 'throughput.block_critical_latency', required: false);
    }

    private function validatePentest(): void
    {
        $pentest = $this->section('pentest', false);
        if ($pentest === null) {
            return;
        }
        foreach (['block_release_on_open_critical', 'block_release_on_open_high'] as $key) {
            $this->bool($pentest, $key, 'pentest.' . $key, required: false);
        }
        if (isset($pentest['default_scope'])) {
            $this->stringList($pentest['default_scope'], 'pentest.default_scope', false);
        }
        if (isset($pentest['report_storage']) && (!$this->isStringLike($pentest['report_storage']) || trim((string)$pentest['report_storage']) === '')) {
            $this->issue('medium', 'invalid_pentest_report_storage', 'pentest.report_storage', 'Pentest report storage path should be a non-empty string.', 'non-empty path string', $pentest['report_storage']);
        }
    }

    private function section(string $name, bool $required): ?array
    {
        if (!array_key_exists($name, $this->config)) {
            if ($required) {
                $this->issue('high', 'missing_section_' . $name, $name, "Missing required config section '{$name}'.", 'array', null);
            }
            return null;
        }
        if (!is_array($this->config[$name])) {
            $this->issue('critical', 'invalid_section_' . $name, $name, "Config section '{$name}' must be an array.", 'array', $this->config[$name]);
            return null;
        }
        return $this->config[$name];
    }

    private function bool(array $section, string $key, string $path, bool $required = true): void
    {
        if (!array_key_exists($key, $section)) {
            if ($required) {
                $this->issue('high', 'missing_' . str_replace('.', '_', $path), $path, "Missing required boolean config '{$path}'.", 'bool', null);
            }
            return;
        }
        if (!is_bool($section[$key])) {
            $this->issue('high', 'invalid_' . str_replace('.', '_', $path), $path, "Config '{$path}' must be boolean true/false after loading.", 'bool', $section[$key]);
        }
    }

    private function positiveInt(array $section, string $key, string $path, bool $required = true): void
    {
        if (!array_key_exists($key, $section)) {
            if ($required) {
                $this->issue('high', 'missing_' . str_replace('.', '_', $path), $path, "Missing required positive integer config '{$path}'.", 'positive int', null);
            }
            return;
        }
        $value = $section[$key];
        if (!is_int($value) && !(is_string($value) && ctype_digit($value))) {
            $this->issue('high', 'invalid_' . str_replace('.', '_', $path), $path, "Config '{$path}' must be a positive integer.", 'positive int', $value);
            return;
        }
        if ((int)$value < 1) {
            $this->issue('high', 'invalid_' . str_replace('.', '_', $path), $path, "Config '{$path}' must be greater than zero.", '> 0', $value);
        }
    }

    private function intRange(array $section, string $key, string $path, int $min, int $max, bool $required = true): void
    {
        if (!array_key_exists($key, $section)) {
            if ($required) {
                $this->issue('high', 'missing_' . str_replace('.', '_', $path), $path, "Missing integer config '{$path}'.", "{$min}-{$max}", null);
            }
            return;
        }
        $value = $section[$key];
        if ((!is_int($value) && !(is_string($value) && ctype_digit($value))) || (int)$value < $min || (int)$value > $max) {
            $this->issue('high', 'invalid_' . str_replace('.', '_', $path), $path, "Config '{$path}' must be an integer between {$min} and {$max}.", "{$min}-{$max}", $value);
        }
    }

    private function positiveNumber(array $section, string $key, string $path, bool $required = true): void
    {
        if (!array_key_exists($key, $section)) {
            if ($required) {
                $this->issue('high', 'missing_' . str_replace('.', '_', $path), $path, "Missing required positive numeric config '{$path}'.", 'positive number', null);
            }
            return;
        }
        $value = $section[$key];
        if (!is_numeric($value) || (float)$value <= 0) {
            $this->issue('high', 'invalid_' . str_replace('.', '_', $path), $path, "Config '{$path}' must be a positive number.", '> 0', $value);
        }
    }

    private function numberRange(array $section, string $key, string $path, float $min, float $max, bool $required = true): void
    {
        if (!array_key_exists($key, $section)) {
            if ($required) {
                $this->issue('high', 'missing_' . str_replace('.', '_', $path), $path, "Missing numeric config '{$path}'.", "{$min}-{$max}", null);
            }
            return;
        }
        $value = $section[$key];
        if (!is_numeric($value) || (float)$value < $min || (float)$value > $max) {
            $this->issue('high', 'invalid_' . str_replace('.', '_', $path), $path, "Config '{$path}' must be a number between {$min} and {$max}.", "{$min}-{$max}", $value);
        }
    }

    private function stringList(mixed $value, string $path, bool $required = true): bool
    {
        if ($value === null || $value === []) {
            if ($required) {
                $this->issue('high', 'missing_' . str_replace('.', '_', $path), $path, "Config '{$path}' must be a non-empty array of strings.", 'string[]', $value);
            }
            return false;
        }
        if (!is_array($value)) {
            $this->issue('high', 'invalid_' . str_replace('.', '_', $path), $path, "Config '{$path}' must be an array of strings.", 'string[]', $value);
            return false;
        }
        foreach ($value as $item) {
            if (!$this->isStringLike($item)) {
                $this->issue('high', 'invalid_item_' . str_replace('.', '_', $path), $path, "Config '{$path}' contains a non-string value.", 'string', $item);
                return false;
            }
        }
        return true;
    }

    private function sqlIdentifier(mixed $value, string $path, string $label): void
    {
        if (!$this->isStringLike($value) || trim((string)$value) === '') {
            $this->issue('high', 'invalid_sql_identifier_' . str_replace('.', '_', $path), $path, "{$label} must be a non-empty SQL identifier string.", 'SQL identifier', $value);
            return;
        }
        try {
            SqlIdentifier::assert((string)$value, $label);
        } catch (Throwable $e) {
            $this->issue('high', 'unsafe_sql_identifier_' . str_replace('.', '_', $path), $path, $e->getMessage(), 'safe SQL identifier', $value);
        }
    }

    private function issue(string $level, string $key, string $path, string $message, mixed $expected = null, mixed $actual = null): void
    {
        $issue = [
            'level' => $level,
            'key' => $key,
            'path' => $path,
            'message' => $message,
        ];
        if ($expected !== null) {
            $issue['expected'] = $expected;
        }
        if ($actual !== null) {
            $issue['actual'] = $this->safeActual($actual);
        }
        $this->issues[] = $issue;
    }

    private function safeActual(mixed $actual): mixed
    {
        if (is_string($actual) && strlen($actual) > 160) {
            return substr($actual, 0, 157) . '...';
        }
        return $actual;
    }

    private function isProduction(array $app): bool
    {
        return (string)($app['env'] ?? 'local') === 'production';
    }

    private function isStringLike(mixed $value): bool
    {
        return is_string($value) || is_int($value) || is_float($value);
    }

    private function looksLikeUrl(string $url): bool
    {
        $parts = parse_url($url);
        return is_array($parts)
            && isset($parts['scheme'], $parts['host'])
            && in_array(strtolower((string)$parts['scheme']), ['http', 'https'], true)
            && (string)$parts['host'] !== '';
    }

    private function isIpOrCidr(string $value): bool
    {
        if (filter_var($value, FILTER_VALIDATE_IP) !== false) {
            return true;
        }
        if (!str_contains($value, '/')) {
            return false;
        }
        [$ip, $bits] = explode('/', $value, 2);
        if (filter_var($ip, FILTER_VALIDATE_IP) === false || !ctype_digit($bits)) {
            return false;
        }
        $maxBits = str_contains($ip, ':') ? 128 : 32;
        return (int)$bits >= 0 && (int)$bits <= $maxBits;
    }
}
