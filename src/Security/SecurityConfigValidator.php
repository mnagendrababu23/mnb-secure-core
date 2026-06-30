<?php
namespace Mnb\SecurityCore\Security;

use Mnb\SecurityCore\Core\StorageDriverResolver;
use Mnb\SecurityCore\Files\UploadSecurityProfile;
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
        $this->validateAudit();
        $this->validateLimits();
        $this->validateUploads();
        $this->validateStores();
        $this->validateRedis();
        $this->validateCors();
        $this->validateSecurityHeaders();
        $this->validateRequestValidation();
        $this->validateAuthentication();
        $this->validateAuthorization();
        $this->validateRequestReceiving();
        $this->validateTrustBoundaries();
        $this->validateSuggestions();
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

    private function validateAudit(): void
    {
        $audit = $this->section('audit', false);
        if ($audit === null) {
            return;
        }

        $this->bool($audit, 'enabled', 'audit.enabled', required: false);
        $this->bool($audit, 'mirror_to_log', 'audit.mirror_to_log', required: false);

        foreach (['file', 'log_file'] as $key) {
            if (!array_key_exists($key, $audit)) {
                if ($key === 'file') {
                    $this->issue('medium', 'missing_audit_file', 'audit.file', 'Audit file is not configured; the kernel will fall back to paths.audit/security-audit.log.', 'path string', null);
                }
                continue;
            }
            if (!$this->isStringLike($audit[$key]) || trim((string)$audit[$key]) === '') {
                $this->issue('high', 'invalid_audit_' . $key, 'audit.' . $key, 'Audit file paths must be non-empty strings.', 'path string', $audit[$key]);
            }
        }

        if (isset($audit['auto'])) {
            if (!is_array($audit['auto'])) {
                $this->issue('high', 'invalid_audit_auto_config', 'audit.auto', 'audit.auto must be a config array when provided.', 'array', $audit['auto']);
            } else {
                foreach (['enabled', 'log_reads', 'log_preflight'] as $key) {
                    $this->bool($audit['auto'], $key, 'audit.auto.' . $key, required: false);
                }
                if (isset($audit['auto']['excluded_paths'])) {
                    $this->stringList($audit['auto']['excluded_paths'], 'audit.auto.excluded_paths', false);
                }
                if (isset($audit['auto']['sensitive_input_keys'])) {
                    $this->stringList($audit['auto']['sensitive_input_keys'], 'audit.auto.sensitive_input_keys', false);
                }
            }
        }

        $paths = is_array($this->config['paths'] ?? null) ? $this->config['paths'] : [];
        if (!empty($audit['file']) && !empty($paths['private_storage']) && str_starts_with((string)$audit['file'], (string)$paths['private_storage'])) {
            $this->issue('medium', 'audit_file_inside_private_storage', 'audit.file', 'Audit logs should be stored in a dedicated audit/log path, not mixed with private uploaded files.', 'dedicated audit path', $audit['file']);
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

        $app = is_array($this->config['app'] ?? null) ? $this->config['app'] : [];
        $isProduction = $this->isProduction($app);
        $profile = $uploads['profile'] ?? 'custom';
        $profileName = is_scalar($profile) ? UploadSecurityProfile::normalizeName((string)$profile) : null;
        $customProfiles = is_array($uploads['profiles'] ?? null) ? $uploads['profiles'] : [];

        if (!$this->isStringLike($profile)) {
            $this->issue('high', 'invalid_upload_profile', 'uploads.profile', 'Upload profile must be a string.', UploadSecurityProfile::names(), $profile);
        } elseif ($profileName !== 'custom' && !UploadSecurityProfile::exists($profileName, $customProfiles)) {
            $this->issue('high', 'unknown_upload_profile', 'uploads.profile', 'Upload profile must be one of the built-in profiles or a custom profile key.', array_merge(['custom'], UploadSecurityProfile::names()), $profile);
        }

        $this->bool($uploads, 'strict_production', 'uploads.strict_production', required: false);
        $this->bool($uploads, 'allow_archives_in_production', 'uploads.allow_archives_in_production', required: false);
        $this->positiveInt($uploads, 'max_archive_entries', 'uploads.max_archive_entries', required: false);
        $this->positiveInt($uploads, 'max_archive_uncompressed_bytes', 'uploads.max_archive_uncompressed_bytes', required: false);

        foreach (['allowed_extensions', 'allowed_mime_prefixes', 'blocked_extensions'] as $key) {
            if (array_key_exists($key, $uploads) || $profileName === 'custom') {
                $this->stringList($uploads[$key] ?? [], 'uploads.' . $key, $key !== 'blocked_extensions');
            }
        }

        $dangerous = ['php', 'phtml', 'phar', 'cgi', 'pl', 'sh', 'exe', 'com', 'bat', 'cmd', 'js', 'html', 'htm', 'svg'];
        $archiveExtensions = ['zip', 'tar', 'gz', 'tgz', 'rar', '7z'];
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

        if (array_key_exists('profiles', $uploads)) {
            if (!is_array($uploads['profiles'])) {
                $this->issue('high', 'invalid_upload_profiles', 'uploads.profiles', 'Upload profiles must be an associative array.', 'array<string,array>', $uploads['profiles']);
            } else {
                foreach ($uploads['profiles'] as $name => $profileConfig) {
                    if (!is_string($name) || !preg_match('/^[a-z0-9][a-z0-9_.:-]{0,80}$/', strtolower($name))) {
                        $this->issue('high', 'invalid_upload_profile_name', 'uploads.profiles', 'Upload profile names must use safe identifier characters.', 'letters, numbers, dash, underscore, dot or colon', $name);
                        continue;
                    }
                    if (!is_array($profileConfig)) {
                        $this->issue('high', 'invalid_upload_profile_config_' . preg_replace('/[^a-z0-9_]+/i', '_', $name), 'uploads.profiles.' . $name, 'Upload profile config must be an array.', 'array', $profileConfig);
                        continue;
                    }
                    $this->validateUploadProfileConfig($name, $profileConfig);
                }
            }
        }

        $archiveProfileSelected = $profileName === UploadSecurityProfile::ARCHIVES;
        $archivesAllowedByLegacyList = array_intersect($allowedExtensions, $archiveExtensions) !== [];
        if ($isProduction && ($archiveProfileSelected || $archivesAllowedByLegacyList) && empty($uploads['allow_archives_in_production'])) {
            $this->issue('high', 'archives_allowed_in_production_without_opt_in', 'uploads', 'Archive uploads are high risk in production and must be explicitly opted in.', 'uploads.allow_archives_in_production=true', ['profile' => $profileName, 'allowed_extensions' => $allowedExtensions]);
        }
        if ($isProduction && empty($uploads['strict_production'])) {
            $this->issue('medium', 'upload_strict_production_disabled', 'uploads.strict_production', 'Enable strict_production so production uploads always randomize names, deny double extensions, and reject executable content.', true, $uploads['strict_production'] ?? null);
        }

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

    /** @param array<string,mixed> $profileConfig */
    private function validateUploadProfileConfig(string $name, array $profileConfig): void
    {
        $path = 'uploads.profiles.' . $name;
        foreach (['allowed_extensions', 'allowed_mime_prefixes', 'blocked_extensions'] as $key) {
            if (array_key_exists($key, $profileConfig)) {
                $this->stringList($profileConfig[$key], $path . '.' . $key, false);
            }
        }
        foreach (['deny_double_extensions', 'randomize_names', 'reject_executable_content', 'strict_mode'] as $key) {
            if (array_key_exists($key, $profileConfig)) {
                $this->bool($profileConfig, $key, $path . '.' . $key, required: false);
            }
        }
        foreach (['max_bytes', 'max_original_name_length', 'max_archive_entries', 'max_archive_uncompressed_bytes'] as $key) {
            if (array_key_exists($key, $profileConfig)) {
                $this->positiveInt($profileConfig, $key, $path . '.' . $key, required: false);
            }
        }

        $dangerous = ['php', 'phtml', 'phar', 'cgi', 'pl', 'sh', 'exe', 'com', 'bat', 'cmd', 'js', 'html', 'htm', 'svg'];
        $allowedExtensions = array_map(fn($ext): string => strtolower(ltrim((string)$ext, '.')), is_array($profileConfig['allowed_extensions'] ?? null) ? $profileConfig['allowed_extensions'] : []);
        $dangerousAllowed = array_values(array_intersect($allowedExtensions, $dangerous));
        if ($dangerousAllowed !== []) {
            $this->issue('critical', 'dangerous_upload_profile_extension_' . preg_replace('/[^a-z0-9_]+/i', '_', $name), $path . '.allowed_extensions', 'Upload profiles must not allow executable or scriptable extensions.', 'safe extensions only', $dangerousAllowed);
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

        $this->bool($cors, 'enabled', 'cors.enabled', required: false);
        $this->bool($cors, 'allow_credentials', 'cors.allow_credentials', required: false);
        $this->bool($cors, 'allow_null_origin', 'cors.allow_null_origin', required: false);
        $this->bool($cors, 'allow_private_network', 'cors.allow_private_network', required: false);
        $this->stringList($cors['allowed_origins'] ?? [], 'cors.allowed_origins', true);
        $this->stringList($cors['allowed_methods'] ?? [], 'cors.allowed_methods', true);
        $this->stringList($cors['allowed_headers'] ?? [], 'cors.allowed_headers', true);
        if (isset($cors['allowed_origin_patterns'])) {
            $this->stringList($cors['allowed_origin_patterns'], 'cors.allowed_origin_patterns', false);
        }
        if (isset($cors['exposed_headers'])) {
            $this->stringList($cors['exposed_headers'], 'cors.exposed_headers', false);
        }
        $this->intRange($cors, 'max_age', 'cors.max_age', 0, 86400, required: false);

        $origins = is_array($cors['allowed_origins'] ?? null) ? $cors['allowed_origins'] : [];
        foreach ($origins as $origin) {
            if (!is_scalar($origin)) {
                continue;
            }
            $origin = trim((string)$origin);
            if ($origin === '*') {
                continue;
            }
            if ($origin === 'null') {
                if (empty($cors['allow_null_origin'])) {
                    $this->issue('medium', 'null_cors_origin_without_opt_in', 'cors.allowed_origins', 'The null origin should only be allowed when cors.allow_null_origin is explicitly true.', 'allow_null_origin=true', $origin);
                }
                continue;
            }
            if (!$this->looksLikeUrl($origin)) {
                $this->issue('medium', 'invalid_cors_origin', 'cors.allowed_origins', 'CORS origins must be explicit http(s) origins such as https://app.example.com.', 'http(s) origin', $origin);
            }
            if (preg_match('/[
]/', $origin)) {
                $this->issue('high', 'cors_origin_header_injection', 'cors.allowed_origins', 'CORS origins must not contain CR/LF characters.', 'single-line origin', $origin);
            }
        }

        if (in_array('*', $origins, true) && !empty($cors['allow_credentials'])) {
            $this->issue('high', 'wildcard_cors_with_credentials', 'cors', 'CORS cannot safely combine wildcard allowed_origins with allow_credentials=true.', 'explicit origins when credentials are enabled', ['allowed_origins' => $origins, 'allow_credentials' => true]);
        }
        if (in_array('*', $origins, true) && $this->isProduction($this->config['app'] ?? [])) {
            $this->issue('medium', 'wildcard_cors_origin', 'cors.allowed_origins', 'Wildcard CORS origins should be avoided in production APIs.', 'explicit origins', '*');
        }

        foreach (['allowed_methods', 'allowed_headers', 'exposed_headers'] as $key) {
            foreach ((array)($cors[$key] ?? []) as $value) {
                if (is_scalar($value) && preg_match('/[
]/', (string)$value)) {
                    $this->issue('high', 'cors_header_injection_' . $key, 'cors.' . $key, 'CORS header config values must not contain CR/LF characters.', 'single-line token', $value);
                }
            }
        }
    }

    private function validateSecurityHeaders(): void
    {
        $headers = $this->section('security_headers', false);
        if ($headers === null) {
            return;
        }

        $this->bool($headers, 'enabled', 'security_headers.enabled', required: false);

        foreach (['content_type_options', 'referrer_policy', 'frame_ancestors', 'x_frame_options', 'cross_origin_opener_policy', 'cross_origin_resource_policy', 'cross_origin_embedder_policy'] as $key) {
            if (isset($headers[$key]) && $headers[$key] !== null && $headers[$key] !== false && !$this->isStringLike($headers[$key])) {
                $this->issue('medium', 'invalid_security_header_' . $key, 'security_headers.' . $key, "security_headers.{$key} should be a string when enabled.", 'string', $headers[$key]);
            }
            if (isset($headers[$key]) && is_string($headers[$key]) && preg_match('/[\r\n]/', $headers[$key])) {
                $this->issue('high', 'header_injection_' . $key, 'security_headers.' . $key, "security_headers.{$key} must not contain CR/LF characters.", 'single-line header value', $headers[$key]);
            }
        }

        $hsts = $headers['hsts'] ?? null;
        if (is_bool($hsts) || $hsts === null) {
            // Legacy boolean config remains supported.
        } elseif (is_array($hsts)) {
            $this->bool($hsts, 'enabled', 'security_headers.hsts.enabled', required: false);
            $this->intRange($hsts, 'max_age', 'security_headers.hsts.max_age', 0, 63072000, required: false);
            $this->bool($hsts, 'include_subdomains', 'security_headers.hsts.include_subdomains', required: false);
            $this->bool($hsts, 'preload', 'security_headers.hsts.preload', required: false);
            $this->bool($hsts, 'only_on_https', 'security_headers.hsts.only_on_https', required: false);
            if (!empty($hsts['preload'])) {
                $maxAge = (int)($hsts['max_age'] ?? 0);
                if ($maxAge < 31536000 || empty($hsts['include_subdomains'])) {
                    $this->issue('medium', 'hsts_preload_requirements_missing', 'security_headers.hsts', 'HSTS preload requires max_age >= 31536000 and include_subdomains=true.', 'preload-ready HSTS settings', $hsts);
                }
            }
        } else {
            $this->issue('high', 'invalid_security_headers_hsts', 'security_headers.hsts', 'security_headers.hsts must be boolean or an HSTS settings array.', 'bool|array', $hsts);
        }

        $app = is_array($this->config['app'] ?? null) ? $this->config['app'] : [];
        if ($this->isProduction($app)) {
            $hstsEnabled = is_bool($hsts) ? $hsts : (is_array($hsts) ? !empty($hsts['enabled']) : false);
            $forceHttps = !empty($app['force_https']) || str_starts_with((string)($app['url'] ?? ''), 'https://');
            if ($forceHttps && !$hstsEnabled) {
                $this->issue('medium', 'hsts_disabled_for_https_production', 'security_headers.hsts.enabled', 'Production HTTPS apps should enable HSTS after confirming HTTPS is stable.', 'true', false);
            }
        }

        $csp = $headers['csp'] ?? null;
        if ($csp === null) {
            return;
        }
        if (is_bool($csp)) {
            return;
        }
        if (!is_array($csp)) {
            $this->issue('high', 'invalid_csp_config', 'security_headers.csp', 'security_headers.csp must be boolean or array.', 'bool|array', $csp);
            return;
        }

        foreach (['enabled', 'report_only', 'nonce_enabled', 'auto_nonce'] as $key) {
            $this->bool($csp, $key, 'security_headers.csp.' . $key, required: false);
        }
        if (isset($csp['nonce_directives'])) {
            $this->stringList($csp['nonce_directives'], 'security_headers.csp.nonce_directives', false);
        }
        if (isset($csp['directives']) && !is_array($csp['directives'])) {
            $this->issue('high', 'invalid_csp_directives', 'security_headers.csp.directives', 'CSP directives must be an associative array.', 'array', $csp['directives']);
        }
        foreach ((array)($csp['directives'] ?? []) as $directive => $sources) {
            $directive = (string)$directive;
            if (!preg_match('/^[a-z][a-z0-9-]*$/', $directive)) {
                $this->issue('high', 'invalid_csp_directive_name', 'security_headers.csp.directives.' . $directive, 'CSP directive names may contain only lowercase letters, numbers, and dashes.', 'safe directive name', $directive);
                continue;
            }
            if (is_string($sources)) {
                $sources = preg_split('/\s+/', trim($sources)) ?: [];
            }
            if (!is_array($sources)) {
                $this->issue('high', 'invalid_csp_sources_' . $directive, 'security_headers.csp.directives.' . $directive, 'CSP directive sources must be a string or array of strings.', 'string|string[]', $sources);
                continue;
            }
            foreach ($sources as $source) {
                if (!$this->isStringLike($source) || trim((string)$source) === '' || str_contains((string)$source, ';') || preg_match('/[\r\n]/', (string)$source)) {
                    $this->issue('high', 'invalid_csp_source_' . $directive, 'security_headers.csp.directives.' . $directive, 'CSP source values must be non-empty single tokens without CR/LF or semicolons.', 'safe CSP source token', $source);
                    break;
                }
            }
            if ($this->isProduction($app) && $directive === 'script-src' && in_array("'unsafe-inline'", $sources, true) && empty($csp['report_only'])) {
                $this->issue('medium', 'csp_script_unsafe_inline', 'security_headers.csp.directives.script-src', "Avoid 'unsafe-inline' in production enforcing CSP. Prefer nonces or hashes.", 'nonce/hash based scripts', $sources);
            }
            if ($this->isProduction($app) && in_array('*', $sources, true) && empty($csp['report_only'])) {
                $this->issue('medium', 'csp_wildcard_source_' . $directive, 'security_headers.csp.directives.' . $directive, 'Avoid wildcard CSP sources in production enforcing mode.', 'explicit sources', $sources);
            }
        }

        $permissions = $headers['permissions_policy'] ?? null;
        if ($permissions !== null && $permissions !== false) {
            if (is_string($permissions)) {
                $permissions = ['preset' => $permissions];
            }
            if (!is_array($permissions)) {
                $this->issue('medium', 'invalid_permissions_policy', 'security_headers.permissions_policy', 'permissions_policy must be a preset string or config array.', 'string|array', $permissions);
            } else {
                $preset = strtolower((string)($permissions['preset'] ?? 'strict'));
                if (!in_array($preset, ['strict', 'balanced', 'minimal', 'custom', 'none', 'disabled', 'off'], true)) {
                    $this->issue('medium', 'unknown_permissions_policy_preset', 'security_headers.permissions_policy.preset', 'Unknown Permissions-Policy preset.', 'strict|balanced|minimal|custom|none', $preset);
                }
                if (isset($permissions['directives']) && !is_array($permissions['directives'])) {
                    $this->issue('medium', 'invalid_permissions_policy_directives', 'security_headers.permissions_policy.directives', 'Permissions-Policy directives must be an associative array.', 'array', $permissions['directives']);
                }
            }
        }
    }


    private function validateRequestValidation(): void
    {
        $validation = $this->section('request_validation', false);
        if ($validation === null) {
            return;
        }

        foreach (['enabled', 'sanitize', 'throw'] as $key) {
            $this->bool($validation, $key, 'request_validation.' . $key, required: false);
        }
        $this->intRange($validation, 'error_status', 'request_validation.error_status', 400, 599, required: false);
        $this->intRange($validation, 'max_depth', 'request_validation.max_depth', 1, 50, required: false);
        $this->intRange($validation, 'max_string_length', 'request_validation.max_string_length', 1, 1048576, required: false);
        if (isset($validation['blocked_keys'])) {
            $this->stringList($validation['blocked_keys'], 'request_validation.blocked_keys', false);
        }
        if (isset($validation['message']) && !$this->isStringLike($validation['message'])) {
            $this->issue('medium', 'invalid_request_validation_message', 'request_validation.message', 'Validation error message should be a string.', 'string', $validation['message']);
        }

        foreach (['default', 'routes'] as $key) {
            if (!array_key_exists($key, $validation)) {
                continue;
            }
            if (!is_array($validation[$key])) {
                $this->issue('high', 'invalid_request_validation_' . $key, 'request_validation.' . $key, 'Request validation policies must be arrays.', 'array', $validation[$key]);
                continue;
            }
        }

        if (isset($validation['default']) && is_array($validation['default'])) {
            $this->validateInputPolicy('request_validation.default', $validation['default']);
        }
        if (isset($validation['routes']) && is_array($validation['routes'])) {
            foreach ($validation['routes'] as $name => $policy) {
                if (!is_string($name) && !is_int($name)) {
                    $this->issue('medium', 'invalid_request_validation_route_key', 'request_validation.routes', 'Route validation keys should be route names or numeric entries.', 'string|int', $name);
                    continue;
                }
                if (!is_array($policy)) {
                    $this->issue('high', 'invalid_request_validation_route_policy', 'request_validation.routes.' . (string)$name, 'Each route validation policy must be an array.', 'array', $policy);
                    continue;
                }
                $this->validateInputPolicy('request_validation.routes.' . (string)$name, $policy);
            }
        }
    }

    /** @param array<string,mixed> $policy */
    private function validateInputPolicy(string $path, array $policy): void
    {
        if (isset($policy['methods'])) {
            $methods = is_array($policy['methods']) ? $policy['methods'] : explode(',', (string)$policy['methods']);
            foreach ($methods as $method) {
                $method = strtoupper(trim((string)$method));
                if (!in_array($method, ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'], true)) {
                    $this->issue('medium', 'invalid_request_validation_method', $path . '.methods', 'Validation policy method should be a known HTTP method.', 'HTTP method', $method);
                    break;
                }
            }
        }
        foreach (['path', 'path_pattern'] as $key) {
            if (isset($policy[$key]) && (!$this->isStringLike($policy[$key]) || trim((string)$policy[$key]) === '')) {
                $this->issue('medium', 'invalid_request_validation_' . $key, $path . '.' . $key, $key . ' should be a non-empty string.', 'string', $policy[$key]);
            }
        }
        if (isset($policy['path_pattern'])) {
            set_error_handler(static fn(): bool => true);
            try {
                $validPattern = preg_match((string)$policy['path_pattern'], '/test') !== false;
            } finally {
                restore_error_handler();
            }
            if (!$validPattern) {
                $this->issue('medium', 'invalid_request_validation_path_pattern', $path . '.path_pattern', 'path_pattern must be a valid PHP regex.', 'valid regex', $policy['path_pattern']);
            }
        }
        foreach (['sanitize', 'throw'] as $key) {
            $this->bool($policy, $key, $path . '.' . $key, required: false);
        }
        $this->intRange($policy, 'max_depth', $path . '.max_depth', 1, 50, required: false);
        $this->intRange($policy, 'max_string_length', $path . '.max_string_length', 1, 1048576, required: false);
        if (isset($policy['blocked_keys'])) {
            $this->stringList($policy['blocked_keys'], $path . '.blocked_keys', false);
        }

        foreach (['query', 'body', 'all'] as $location) {
            if (!isset($policy[$location])) {
                continue;
            }
            if (!is_array($policy[$location])) {
                $this->issue('high', 'invalid_request_validation_location_' . $location, $path . '.' . $location, 'Input validation location config must be an array.', 'array', $policy[$location]);
                continue;
            }
            $this->validateInputLocationPolicy($path . '.' . $location, $policy[$location]);
        }
    }

    /** @param array<string,mixed> $location */
    private function validateInputLocationPolicy(string $path, array $location): void
    {
        foreach (['sanitize', 'strict'] as $key) {
            $this->bool($location, $key, $path . '.' . $key, required: false);
        }
        if (isset($location['allowed_fields'])) {
            $this->stringList($location['allowed_fields'], $path . '.allowed_fields', false);
        }
        foreach (['rules', 'sanitize_rules'] as $key) {
            if (!isset($location[$key])) {
                continue;
            }
            if (!is_array($location[$key])) {
                $this->issue('high', 'invalid_' . str_replace('.', '_', $path) . '_' . $key, $path . '.' . $key, $key . ' must be an associative array.', 'array<string,string|array>', $location[$key]);
                continue;
            }
            foreach ($location[$key] as $field => $rule) {
                if (!is_string($field) || trim($field) === '' || preg_match('/[\r\n]/', $field)) {
                    $this->issue('medium', 'invalid_input_rule_field', $path . '.' . $key, 'Input rule field names must be safe strings.', 'field name', $field);
                    break;
                }
                if (!is_string($rule) && !is_array($rule)) {
                    $this->issue('medium', 'invalid_input_rule_value', $path . '.' . $key . '.' . $field, 'Input rules must be pipe-delimited strings or arrays.', 'string|array', $rule);
                    break;
                }
            }
        }
    }



    private function validateAuthentication(): void
    {
        $auth = $this->section('authentication', false);
        if ($auth === null) {
            return;
        }
        $this->bool($auth, 'enabled', 'authentication.enabled', required: false);
        if (isset($auth['defaults'])) {
            if (!is_array($auth['defaults'])) {
                $this->issue('high', 'invalid_authentication_defaults', 'authentication.defaults', 'Authentication defaults must be an array.', 'array', $auth['defaults']);
            } else {
                $this->validateAuthenticationStrategy('authentication.defaults', $auth['defaults'], allowMissingType: true);
            }
        }
        if (!isset($auth['strategies']) || !is_array($auth['strategies']) || $auth['strategies'] === []) {
            $this->issue('medium', 'missing_authentication_strategies', 'authentication.strategies', 'Define named authentication strategies such as api_bearer, optional_bearer, admin_bearer, web_session, webhook_hmac, and internal_system.', 'non-empty strategies array', $auth['strategies'] ?? null);
        } else {
            foreach ($auth['strategies'] as $name => $strategy) {
                if (!is_string($name) || !preg_match('/^[a-z][a-z0-9_.:-]{1,95}$/', $name)) {
                    $this->issue('high', 'invalid_authentication_strategy_name', 'authentication.strategies', 'Authentication strategy names must be safe slugs.', 'safe strategy slug', $name);
                    continue;
                }
                if (!is_array($strategy)) {
                    $this->issue('high', 'invalid_authentication_strategy', 'authentication.strategies.' . $name, 'Authentication strategy must be an array.', 'array', $strategy);
                    continue;
                }
                $this->validateAuthenticationStrategy('authentication.strategies.' . $name, $strategy);
                if ($this->isProduction($this->config['app'] ?? []) && str_contains($name, 'admin') && (($strategy['type'] ?? 'bearer') === 'none' || !($strategy['required'] ?? true))) {
                    $this->issue('high', 'unsafe_admin_authentication_strategy', 'authentication.strategies.' . $name, 'Admin authentication strategies must require credentials in production.', 'required auth strategy', $strategy);
                }
            }
        }
        if (isset($auth['password_policy'])) {
            if (!is_array($auth['password_policy'])) {
                $this->issue('high', 'invalid_password_policy', 'authentication.password_policy', 'Password policy must be an array.', 'array', $auth['password_policy']);
            } else {
                $policy = $auth['password_policy'];
                $this->intRange($policy, 'min_length', 'authentication.password_policy.min_length', 8, 256, required: false);
                $this->intRange($policy, 'max_length', 'authentication.password_policy.max_length', 8, 1024, required: false);
                foreach (['require_mixed_case', 'require_number', 'require_symbol', 'block_common_passwords', 'block_user_context'] as $key) {
                    $this->bool($policy, $key, 'authentication.password_policy.' . $key, required: false);
                }
                if (isset($policy['min_length'], $policy['max_length']) && (int)$policy['min_length'] > (int)$policy['max_length']) {
                    $this->issue('high', 'invalid_password_policy_lengths', 'authentication.password_policy', 'Password min_length must be less than or equal to max_length.', 'min <= max', $policy);
                }
            }
        }
        if (isset($auth['login'])) {
            if (!is_array($auth['login'])) {
                $this->issue('high', 'invalid_authentication_login', 'authentication.login', 'Authentication login config must be an array.', 'array', $auth['login']);
            } else {
                if (isset($auth['login']['rate_policy']) && (!$this->isStringLike($auth['login']['rate_policy']) || trim((string)$auth['login']['rate_policy']) === '')) {
                    $this->issue('medium', 'invalid_login_rate_policy', 'authentication.login.rate_policy', 'Login rate policy must be a non-empty string.', 'rate policy name', $auth['login']['rate_policy']);
                }
                $this->intRange($auth['login'], 'ttl_seconds', 'authentication.login.ttl_seconds', 60, 315360000, required: false);
            }
        }
    }

    /** @param array<string,mixed> $strategy */
    private function validateAuthenticationStrategy(string $path, array $strategy, bool $allowMissingType = false): void
    {
        foreach (['required', 'audit'] as $key) {
            $this->bool($strategy, $key, $path . '.' . $key, required: false);
        }
        if (isset($strategy['type'])) {
            $type = (string)$strategy['type'];
            if (!in_array($type, ['none', 'bearer', 'optional_bearer', 'session', 'signature'], true)) {
                $this->issue('high', 'invalid_authentication_strategy_type', $path . '.type', 'Authentication strategy type must be none, bearer, optional_bearer, session, or signature.', 'none|bearer|optional_bearer|session|signature', $type);
            }
        } elseif (!$allowMissingType) {
            $this->issue('medium', 'missing_authentication_strategy_type', $path . '.type', 'Authentication strategy should declare a type.', 'auth strategy type', null);
        }
        foreach (['scopes', 'roles', 'permissions'] as $key) {
            if (isset($strategy[$key])) {
                $this->stringList($strategy[$key], $path . '.' . $key, false);
            }
        }
        foreach (['rate_policy', 'failure_message'] as $key) {
            if (isset($strategy[$key]) && $strategy[$key] !== null && (!$this->isStringLike($strategy[$key]) || preg_match('/[\r\n]/', (string)$strategy[$key]))) {
                $this->issue('medium', 'invalid_authentication_' . $key, $path . '.' . $key, $key . ' must be a safe single-line string when provided.', 'safe string', $strategy[$key]);
            }
        }
        if (($strategy['type'] ?? null) === 'signature') {
            $signature = is_array($strategy['signature'] ?? null) ? $strategy['signature'] : (is_array($this->config['request_receiving']['webhook'] ?? null) ? $this->config['request_receiving']['webhook'] : []);
            if ($this->isProduction($this->config['app'] ?? []) && empty($signature['secret'])) {
                $this->issue('high', 'missing_authentication_signature_secret', $path . '.signature.secret', 'Signature authentication strategies require a secret in production.', 'non-empty secret', null);
            }
        }
    }



    private function validateAuthorization(): void
    {
        $authz = $this->section('authorization', false);
        if ($authz === null) {
            return;
        }
        foreach (['enabled', 'deny_by_default', 'audit_denials', 'hide_denial_reasons'] as $key) {
            $this->bool($authz, $key, 'authorization.' . $key, required: false);
        }
        if (!isset($authz['policies']) || !is_array($authz['policies']) || $authz['policies'] === []) {
            $this->issue('medium', 'missing_authorization_policies', 'authorization.policies', 'Define named authorization policies for protected routes and resources.', 'non-empty policy array', $authz['policies'] ?? null);
            return;
        }
        $validClasses = ['public', 'internal', 'confidential', 'sensitive', 'highly_sensitive'];
        foreach ($authz['policies'] as $name => $policy) {
            if (!is_string($name) || !preg_match('/^[a-z][a-z0-9_.:-]{1,95}$/', $name)) {
                $this->issue('high', 'invalid_authorization_policy_name', 'authorization.policies', 'Authorization policy names must be safe slugs.', 'safe policy slug', $name);
                continue;
            }
            if (!is_array($policy)) {
                $this->issue('high', 'invalid_authorization_policy', 'authorization.policies.' . $name, 'Authorization policy must be an array.', 'array', $policy);
                continue;
            }
            $path = 'authorization.policies.' . $name;
            if (isset($policy['resource']) && $policy['resource'] !== null && (!$this->isStringLike($policy['resource']) || !preg_match('/^[A-Za-z_][A-Za-z0-9_:-]*$/', (string)$policy['resource']))) {
                $this->issue('high', 'invalid_authorization_resource', $path . '.resource', 'Authorization policy resource must be a safe resource name.', 'safe resource name', $policy['resource']);
            }
            if (!$this->stringList($policy['actions'] ?? [], $path . '.actions')) {
                continue;
            }
            foreach ((array)($policy['actions'] ?? []) as $action) {
                if (!$this->isStringLike($action) || !preg_match('/^[A-Za-z][A-Za-z0-9_.:-]*$/', (string)$action)) {
                    $this->issue('high', 'invalid_authorization_action', $path . '.actions', 'Authorization actions must be safe action names.', 'safe action', $action);
                }
            }
            foreach (['roles', 'permissions', 'scopes', 'data_classes'] as $listKey) {
                if (isset($policy[$listKey])) {
                    $this->stringList($policy[$listKey], $path . '.' . $listKey, false);
                }
            }
            foreach ((array)($policy['data_classes'] ?? []) as $class) {
                if (!in_array((string)$class, $validClasses, true) && (string)$class !== '*') {
                    $this->issue('high', 'invalid_authorization_data_class', $path . '.data_classes', 'Authorization policy uses an unknown data class.', implode('|', $validClasses), $class);
                }
            }
            foreach (['tenant_required', 'audit'] as $boolKey) {
                $this->bool($policy, $boolKey, $path . '.' . $boolKey, required: false);
            }
            if (isset($policy['trust_boundary']) && $policy['trust_boundary'] !== null && (!$this->isStringLike($policy['trust_boundary']) || preg_match('/[\r\n]/', (string)$policy['trust_boundary']))) {
                $this->issue('medium', 'invalid_authorization_trust_boundary', $path . '.trust_boundary', 'trust_boundary must be a safe single-line string.', 'safe policy name', $policy['trust_boundary']);
            }
            if (isset($policy['fields'])) {
                if (!is_array($policy['fields'])) {
                    $this->issue('high', 'invalid_authorization_fields', $path . '.fields', 'Authorization fields must be an array.', 'array', $policy['fields']);
                } else {
                    foreach (['read', 'write'] as $mode) {
                        if (!isset($policy['fields'][$mode])) { continue; }
                        if (!is_array($policy['fields'][$mode])) {
                            $this->issue('high', 'invalid_authorization_field_mode', $path . '.fields.' . $mode, 'Field authorization mode must be an array.', 'array', $policy['fields'][$mode]);
                            continue;
                        }
                        foreach ($policy['fields'][$mode] as $principal => $fields) {
                            if (!is_string($principal) || preg_match('/[\r\n]/', $principal)) {
                                $this->issue('high', 'invalid_authorization_field_principal', $path . '.fields.' . $mode, 'Field authorization principal must be a safe string.', 'role/scope/permission principal', $principal);
                            }
                            $this->stringList($fields, $path . '.fields.' . $mode . '.' . (string)$principal, false);
                        }
                    }
                }
            }
        }
    }

    private function validateRequestReceiving(): void
    {
        $receiving = $this->section('request_receiving', false);
        if ($receiving === null) {
            return;
        }
        $this->bool($receiving, 'enabled', 'request_receiving.enabled', required: false);
        $this->bool($receiving, 'reject_body_on_get', 'request_receiving.reject_body_on_get', required: false);
        $this->intRange($receiving, 'json_depth', 'request_receiving.json_depth', 1, 512, required: false);
        $this->intRange($receiving, 'json_max_bytes', 'request_receiving.json_max_bytes', 1, 104857600, required: false);
        $this->bool($receiving, 'json_require_object', 'request_receiving.json_require_object', required: false);
        if (isset($receiving['blocked_methods'])) {
            if ($this->stringList($receiving['blocked_methods'], 'request_receiving.blocked_methods', false)) {
                foreach ((array)$receiving['blocked_methods'] as $method) {
                    $method = strtoupper(trim((string)$method));
                    if (!preg_match('/^[A-Z]{3,12}$/', $method)) {
                        $this->issue('medium', 'invalid_blocked_http_method', 'request_receiving.blocked_methods', 'Blocked HTTP methods must be safe method tokens.', 'HTTP method token', $method);
                    }
                }
            }
        }
        if (isset($receiving['request_id'])) {
            if (!is_array($receiving['request_id'])) {
                $this->issue('high', 'invalid_request_receiving_request_id', 'request_receiving.request_id', 'request_id config must be an array.', 'array', $receiving['request_id']);
            } else {
                $rid = $receiving['request_id'];
                if (isset($rid['header']) && (!$this->isStringLike($rid['header']) || preg_match('/[\r\n]/', (string)$rid['header']))) {
                    $this->issue('high', 'invalid_request_id_header', 'request_receiving.request_id.header', 'Request ID header must be a safe single-line string.', 'header name', $rid['header']);
                }
                $this->bool($rid, 'accept_incoming', 'request_receiving.request_id.accept_incoming', required: false);
                $this->intRange($rid, 'max_length', 'request_receiving.request_id.max_length', 16, 256, required: false);
            }
        }
        if (isset($receiving['suspicious'])) {
            if (!is_array($receiving['suspicious'])) {
                $this->issue('high', 'invalid_suspicious_request_config', 'request_receiving.suspicious', 'Suspicious request config must be an array.', 'array', $receiving['suspicious']);
            } else {
                $mode = (string)($receiving['suspicious']['mode'] ?? 'block');
                if (!in_array($mode, ['block', 'audit'], true)) {
                    $this->issue('medium', 'invalid_suspicious_request_mode', 'request_receiving.suspicious.mode', 'Suspicious request mode must be block or audit.', 'block|audit', $mode);
                }
                $this->intRange($receiving['suspicious'], 'max_path_length', 'request_receiving.suspicious.max_path_length', 64, 8192, required: false);
                $this->intRange($receiving['suspicious'], 'max_parameters', 'request_receiving.suspicious.max_parameters', 1, 5000, required: false);
            }
        }
        if (isset($receiving['webhook'])) {
            if (!is_array($receiving['webhook'])) {
                $this->issue('high', 'invalid_webhook_receiving_config', 'request_receiving.webhook', 'Webhook receiving config must be an array.', 'array', $receiving['webhook']);
            } else {
                foreach (['signature_header', 'timestamp_header', 'algorithm'] as $key) {
                    if (isset($receiving['webhook'][$key]) && (!$this->isStringLike($receiving['webhook'][$key]) || preg_match('/[\r\n]/', (string)$receiving['webhook'][$key]))) {
                        $this->issue('high', 'invalid_webhook_' . $key, 'request_receiving.webhook.' . $key, 'Webhook config values must be safe single-line strings.', 'string', $receiving['webhook'][$key]);
                    }
                }
                $this->intRange($receiving['webhook'], 'tolerance_seconds', 'request_receiving.webhook.tolerance_seconds', 0, 86400, required: false);
                $algorithm = strtolower((string)($receiving['webhook']['algorithm'] ?? 'sha256'));
                if (!in_array($algorithm, hash_hmac_algos(), true)) {
                    $this->issue('high', 'invalid_webhook_algorithm', 'request_receiving.webhook.algorithm', 'Webhook HMAC algorithm is not supported by PHP.', 'hash_hmac algorithm', $algorithm);
                }
            }
        }
        if (isset($receiving['defaults'])) {
            if (!is_array($receiving['defaults'])) {
                $this->issue('high', 'invalid_request_receiving_defaults', 'request_receiving.defaults', 'Request receiving defaults must be an array.', 'array', $receiving['defaults']);
            } else {
                $this->validateReceivingProfile('request_receiving.defaults', $receiving['defaults'], allowMissingMethods: true);
            }
        }
        if (!isset($receiving['profiles']) || !is_array($receiving['profiles']) || $receiving['profiles'] === []) {
            $this->issue('medium', 'missing_request_receiving_profiles', 'request_receiving.profiles', 'Define named request receiving profiles such as api_authenticated, public_form, upload_image, and webhook.', 'non-empty profiles array', $receiving['profiles'] ?? null);
            return;
        }
        foreach ($receiving['profiles'] as $name => $profile) {
            if (!is_string($name) || !preg_match('/^[a-z][a-z0-9_.:-]{1,95}$/', $name)) {
                $this->issue('high', 'invalid_request_receiving_profile_name', 'request_receiving.profiles', 'Request receiving profile names must be safe slugs.', 'safe profile slug', $name);
                continue;
            }
            if (!is_array($profile)) {
                $this->issue('high', 'invalid_request_receiving_profile', 'request_receiving.profiles.' . $name, 'Request receiving profile must be an array.', 'array', $profile);
                continue;
            }
            $this->validateReceivingProfile('request_receiving.profiles.' . $name, $profile);
        }
    }

    /** @param array<string,mixed> $profile */
    private function validateReceivingProfile(string $path, array $profile, bool $allowMissingMethods = false): void
    {
        foreach (['request_id', 'request_trust', 'origin_protection', 'https', 'trusted_host', 'cors', 'security_headers', 'json_body', 'suspicious_detection', 'input_validation', 'auto_audit', 'csrf'] as $key) {
            $this->bool($profile, $key, $path . '.' . $key, required: false);
        }
        if (isset($profile['methods'])) {
            $this->validateHttpMethodList($profile['methods'], $path . '.methods');
        } elseif (!$allowMissingMethods) {
            $this->issue('medium', 'request_receiving_profile_missing_methods', $path . '.methods', 'Receiving profiles should declare allowed HTTP methods.', 'HTTP method list', null);
        }
        $this->positiveInt($profile, 'max_bytes', $path . '.max_bytes', required: false);
        if (isset($profile['content_types'])) {
            $this->stringList($profile['content_types'], $path . '.content_types', false);
        }
        if (isset($profile['rate_policy']) && $profile['rate_policy'] !== null && (!$this->isStringLike($profile['rate_policy']) || trim((string)$profile['rate_policy']) === '')) {
            $this->issue('medium', 'invalid_request_receiving_rate_policy', $path . '.rate_policy', 'rate_policy must be a non-empty string when provided.', 'rate policy name', $profile['rate_policy']);
        }
        if (isset($profile['auth']) && $profile['auth'] !== null && $profile['auth'] !== '') {
            $auth = (string)$profile['auth'];
            if (!in_array($auth, ['bearer', 'csrf', 'signature', 'none'], true)) {
                $this->issue('high', 'invalid_request_receiving_auth', $path . '.auth', 'auth must be bearer, csrf, signature, none, or null.', 'bearer|csrf|signature|none|null', $auth);
            }
        }
        foreach (['trust_boundary', 'authorization', 'authorization_action', 'authorization_resource', 'authorization_data_class', 'upload_profile', 'route_name', 'action', 'data_class', 'resource', 'auth_strategy'] as $key) {
            if (isset($profile[$key]) && $profile[$key] !== null && (!$this->isStringLike($profile[$key]) || preg_match('/[\r\n]/', (string)$profile[$key]))) {
                $this->issue('medium', 'invalid_request_receiving_' . $key, $path . '.' . $key, $key . ' must be a safe string when provided.', 'safe string', $profile[$key]);
            }
        }
        if (($profile['auth'] ?? null) === 'signature') {
            $webhook = is_array($profile['webhook'] ?? null) ? $profile['webhook'] : (is_array($this->config['request_receiving']['webhook'] ?? null) ? $this->config['request_receiving']['webhook'] : []);
            if ($this->isProduction($this->config['app'] ?? []) && empty($webhook['secret'])) {
                $this->issue('high', 'missing_webhook_secret_for_signature_profile', $path . '.auth', 'Signature-auth receiving profiles require WEBHOOK_SECRET in production.', 'non-empty webhook secret', null);
            }
        }
    }

    private function validateHttpMethodList(mixed $value, string $path): void
    {
        if (!$this->stringList($value, $path, false)) {
            return;
        }
        foreach ((array)$value as $method) {
            $method = strtoupper(trim((string)$method));
            if (!in_array($method, ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'], true)) {
                $this->issue('medium', 'invalid_http_method_' . str_replace('.', '_', $path), $path, 'HTTP method should be one of GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD.', 'known HTTP method', $method);
            }
        }
    }

    private function validateTrustBoundaries(): void
    {
        $trust = $this->section('trust_boundaries', false);
        if ($trust === null) {
            return;
        }

        foreach (['enabled', 'hide_denial_reasons', 'deny_unclassified_fields'] as $key) {
            $this->bool($trust, $key, 'trust_boundaries.' . $key, required: false);
        }

        $validZones = ['public', 'authenticated', 'school_admin', 'super_admin', 'internal_system'];
        $validClasses = ['public', 'internal', 'confidential', 'sensitive', 'highly_sensitive'];

        if (isset($trust['zones'])) {
            $this->stringList($trust['zones'], 'trust_boundaries.zones', false);
            foreach ((array)$trust['zones'] as $zone) {
                if (is_scalar($zone) && !in_array((string)$zone, $validZones, true)) {
                    $this->issue('medium', 'unknown_trust_zone', 'trust_boundaries.zones', 'Trust boundary zone is not one of the built-in zones.', implode('|', $validZones), $zone);
                }
            }
        }

        if (isset($trust['zone_data_access']) && is_array($trust['zone_data_access'])) {
            foreach ($trust['zone_data_access'] as $zone => $classes) {
                if (!is_string($zone) || !preg_match('/^[a-z][a-z0-9_:-]{1,95}$/', $zone)) {
                    $this->issue('high', 'invalid_trust_zone_access_name', 'trust_boundaries.zone_data_access', 'Trust zone access names must be safe slugs.', 'safe zone slug', $zone);
                    continue;
                }
                if (!$this->stringList($classes, 'trust_boundaries.zone_data_access.' . $zone, false)) {
                    continue;
                }
                foreach ((array)$classes as $class) {
                    if (is_scalar($class) && !in_array((string)$class, $validClasses, true)) {
                        $this->issue('high', 'invalid_trust_zone_data_class', 'trust_boundaries.zone_data_access.' . $zone, 'Trust zone data access contains an unknown data class.', implode('|', $validClasses), $class);
                    }
                }
            }
        } elseif (isset($trust['zone_data_access'])) {
            $this->issue('high', 'invalid_trust_zone_data_access', 'trust_boundaries.zone_data_access', 'Trust boundary zone_data_access must be an associative array.', 'array', $trust['zone_data_access']);
        }

        if (isset($trust['resources']) && is_array($trust['resources'])) {
            foreach ($trust['resources'] as $name => $resource) {
                if (!is_string($name) || !preg_match('/^[a-z][a-z0-9_.:-]{1,95}$/', $name)) {
                    $this->issue('high', 'invalid_trust_resource_name', 'trust_boundaries.resources', 'Trust resource names must be safe slugs.', 'safe resource slug', $name);
                    continue;
                }
                if (!is_array($resource)) {
                    $this->issue('high', 'invalid_trust_resource', 'trust_boundaries.resources.' . $name, 'Trust resource config must be an array.', 'array', $resource);
                    continue;
                }
                $class = $resource['data_class'] ?? null;
                if (!is_scalar($class) || !in_array((string)$class, $validClasses, true)) {
                    $this->issue('high', 'invalid_trust_resource_data_class', 'trust_boundaries.resources.' . $name . '.data_class', 'Trust resource data_class must be known.', implode('|', $validClasses), $class);
                }
                if (isset($resource['tenant_scoped'])) {
                    $this->bool($resource, 'tenant_scoped', 'trust_boundaries.resources.' . $name . '.tenant_scoped', required: false);
                }
                if (isset($resource['fields'])) {
                    if (!is_array($resource['fields'])) {
                        $this->issue('high', 'invalid_trust_resource_fields', 'trust_boundaries.resources.' . $name . '.fields', 'Trust resource fields must map field names to data classes.', 'array', $resource['fields']);
                    } else {
                        foreach ($resource['fields'] as $field => $fieldClass) {
                            if (!is_string($field) || !preg_match('/^[A-Za-z_][A-Za-z0-9_]{0,95}$/', $field)) {
                                $this->issue('high', 'invalid_trust_resource_field_name', 'trust_boundaries.resources.' . $name . '.fields', 'Field names must be safe identifiers.', 'field_name', $field);
                            }
                            if (!is_scalar($fieldClass) || !in_array((string)$fieldClass, $validClasses, true)) {
                                $this->issue('high', 'invalid_trust_resource_field_class', 'trust_boundaries.resources.' . $name . '.fields.' . (string)$field, 'Field data classification must be known.', implode('|', $validClasses), $fieldClass);
                            }
                        }
                    }
                }
            }
        } elseif (isset($trust['resources'])) {
            $this->issue('high', 'invalid_trust_resources', 'trust_boundaries.resources', 'Trust resources must be an associative array.', 'array', $trust['resources']);
        }

        if (!isset($trust['rules']) || !is_array($trust['rules']) || $trust['rules'] === []) {
            $this->issue('medium', 'missing_trust_boundary_rules', 'trust_boundaries.rules', 'Define trust boundary rules for protected resources.', 'non-empty rules array', $trust['rules'] ?? null);
            return;
        }

        foreach ($trust['rules'] as $name => $rule) {
            if (!is_string($name) || !preg_match('/^[a-z][a-z0-9_.:-]{1,95}$/', $name)) {
                $this->issue('high', 'invalid_trust_boundary_policy_name', 'trust_boundaries.rules', 'Trust boundary policy names must be safe slugs.', 'safe policy slug', $name);
                continue;
            }
            if (!is_array($rule)) {
                $this->issue('high', 'invalid_trust_boundary_rule', 'trust_boundaries.rules.' . $name, 'Trust boundary rule must be an array.', 'array', $rule);
                continue;
            }
            foreach (['zones', 'data_classes', 'actions'] as $listKey) {
                if (!$this->stringList($rule[$listKey] ?? [], 'trust_boundaries.rules.' . $name . '.' . $listKey)) {
                    continue;
                }
            }
            foreach ((array)($rule['zones'] ?? []) as $zone) {
                if (is_scalar($zone) && (string)$zone !== '*' && !in_array((string)$zone, $validZones, true)) {
                    $this->issue('high', 'invalid_trust_rule_zone', 'trust_boundaries.rules.' . $name . '.zones', 'Trust boundary rule uses an unknown zone.', implode('|', $validZones), $zone);
                }
            }
            foreach ((array)($rule['data_classes'] ?? []) as $class) {
                if (is_scalar($class) && (string)$class !== '*' && !in_array((string)$class, $validClasses, true)) {
                    $this->issue('high', 'invalid_trust_rule_data_class', 'trust_boundaries.rules.' . $name . '.data_classes', 'Trust boundary rule uses an unknown data class.', implode('|', $validClasses), $class);
                }
            }
            foreach (['resources', 'permissions', 'scopes', 'roles'] as $optionalListKey) {
                if (isset($rule[$optionalListKey])) {
                    $this->stringList($rule[$optionalListKey], 'trust_boundaries.rules.' . $name . '.' . $optionalListKey, false);
                }
            }
            foreach (['tenant_required', 'audit'] as $boolKey) {
                $this->bool($rule, $boolKey, 'trust_boundaries.rules.' . $name . '.' . $boolKey, required: false);
            }
            if (isset($rule['deny_message']) && (!$this->isStringLike($rule['deny_message']) || preg_match('/[\r\n]/', (string)$rule['deny_message']))) {
                $this->issue('medium', 'invalid_trust_deny_message', 'trust_boundaries.rules.' . $name . '.deny_message', 'Trust boundary deny messages must be single-line strings.', 'single-line string', $rule['deny_message']);
            }
        }
    }

    private function validateSuggestions(): void
    {
        $suggestions = $this->section('suggestions', false);
        if ($suggestions === null) {
            return;
        }
        $this->bool($suggestions, 'enabled', 'suggestions.enabled', required: false);
        $this->intRange($suggestions, 'max_results', 'suggestions.max_results', 1, 50, required: false);
        if (isset($suggestions['rules']) && !is_array($suggestions['rules'])) {
            $this->issue('medium', 'invalid_suggestion_rules', 'suggestions.rules', 'suggestions.rules must be an array when provided.', 'array', $suggestions['rules']);
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
