<?php
namespace Mnb\SecurityCore\Security;

use Mnb\SecurityCore\Env\SecretScanner;
use Mnb\SecurityCore\Core\SecurityKernel;
use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\SecurityHeadersBuilder;
use Throwable;

class SecurityDoctor
{
    /** @var array<int,array<string,mixed>> */
    private array $issues = [];

    /** @var array<string,array<string,mixed>> */
    private array $sections = [];

    public function __construct(private array $config, private ?string $projectRoot = null)
    {
        $this->projectRoot = $this->projectRoot !== null ? rtrim($this->projectRoot, DIRECTORY_SEPARATOR) : dirname(__DIR__, 2);
    }

    /** @return array{passed:bool,summary:array<string,mixed>,sections:array<string,array<string,mixed>>,issues:array<int,array<string,mixed>>} */
    public function check(): array
    {
        $this->issues = [];
        $this->sections = [];

        $this->checkPhpRuntime();
        $this->checkConfigValidation();
        $this->checkProductionReadiness();
        $this->checkStoragePaths();
        $this->checkStorageDrivers();
        $this->checkSecurityHeaders();
        $this->checkUploadScanner();
        $this->checkPublicPackage();
        $this->checkSecrets();
        $this->checkVulnerabilityCoverage();

        $counts = $this->countByLevel($this->issues);
        $blocking = ($counts['critical'] ?? 0) + ($counts['high'] ?? 0);

        return [
            'passed' => $blocking === 0,
            'summary' => [
                'project_root' => $this->projectRoot,
                'environment' => (string)($this->config['app']['env'] ?? 'local'),
                'php_version' => PHP_VERSION,
                'blocking_issues' => $blocking,
                'issue_counts' => $counts,
                'sections_total' => count($this->sections),
                'sections_passed' => count(array_filter($this->sections, fn(array $section): bool => (bool)($section['passed'] ?? false))),
            ],
            'sections' => $this->sections,
            'issues' => $this->issues,
        ];
    }

    private function checkPhpRuntime(): void
    {
        $checks = [];
        $issuesBefore = count($this->issues);

        $checks[] = $this->checkItem('php_version', version_compare(PHP_VERSION, '8.1.0', '>='), 'PHP >= 8.1', PHP_VERSION);
        if (version_compare(PHP_VERSION, '8.1.0', '<')) {
            $this->issue('critical', 'php_version_too_old', 'php_runtime', 'PHP 8.1 or newer is required.', ['current' => PHP_VERSION]);
        }

        foreach (['openssl', 'fileinfo', 'json', 'pdo'] as $extension) {
            $loaded = extension_loaded($extension);
            $checks[] = $this->checkItem('ext_' . $extension, $loaded, 'Required PHP extension: ' . $extension, $loaded ? 'loaded' : 'missing');
            if (!$loaded) {
                $this->issue('critical', 'missing_ext_' . $extension, 'php_runtime', 'Required PHP extension is missing: ' . $extension . '.', ['extension' => $extension]);
            }
        }

        foreach (['redis', 'zip'] as $extension) {
            $loaded = extension_loaded($extension);
            $checks[] = $this->checkItem('optional_ext_' . $extension, $loaded, 'Optional PHP extension: ' . $extension, $loaded ? 'loaded' : 'missing');
            if (!$loaded && $this->extensionIsUseful($extension)) {
                $this->issue('medium', 'optional_ext_' . $extension . '_missing', 'php_runtime', 'Optional extension is missing but configured features may need it: ' . $extension . '.', ['extension' => $extension]);
            }
        }

        $procOpenEnabled = function_exists('proc_open') && $this->functionAllowed('proc_open');
        $checks[] = $this->checkItem('proc_open', $procOpenEnabled, 'proc_open available for ClamAV timeout control', $procOpenEnabled ? 'available' : 'disabled');
        $scannerDriver = (string)($this->config['uploads']['scanner']['driver'] ?? 'heuristic');
        if (in_array($scannerDriver, ['clamav', 'composite'], true) && !$procOpenEnabled) {
            $this->issue('high', 'proc_open_disabled_for_clamav', 'php_runtime', 'proc_open is required for ClamAV scanner execution and timeout enforcement.', ['scanner_driver' => $scannerDriver]);
        }

        $this->section('php_runtime', 'PHP Runtime', $checks, $issuesBefore);
    }

    private function checkConfigValidation(): void
    {
        $checks = [];
        $issuesBefore = count($this->issues);
        try {
            $report = (new SecurityConfigValidator($this->config))->validate();
            $checks[] = $this->checkItem('config_validator', (bool)$report['passed'], 'SecurityConfigValidator result', $report['passed'] ? 'passed' : 'failed');
            foreach ((array)($report['issues'] ?? []) as $issue) {
                $this->issue(
                    $this->normalizeLevel((string)($issue['level'] ?? 'medium')),
                    (string)($issue['key'] ?? 'config_issue'),
                    'config_validation',
                    (string)($issue['message'] ?? 'Security config validation issue.'),
                    $issue
                );
            }
        } catch (Throwable $e) {
            $checks[] = $this->checkItem('config_validator', false, 'SecurityConfigValidator result', $e->getMessage());
            $this->issue('critical', 'config_validator_failed', 'config_validation', 'Security config validator failed: ' . $e->getMessage());
        }
        $this->section('config_validation', 'Config Validation', $checks, $issuesBefore);
    }

    private function checkProductionReadiness(): void
    {
        $checks = [];
        $issuesBefore = count($this->issues);
        try {
            $report = (new ProductionSecurityChecker($this->config, $this->projectRoot))->check();
            $checks[] = $this->checkItem('production_checker', (bool)$report['passed'], 'ProductionSecurityChecker result', $report['passed'] ? 'passed' : 'has issues');
            foreach ((array)($report['issues'] ?? []) as $issue) {
                $this->issue(
                    $this->normalizeLevel((string)($issue['level'] ?? 'medium')),
                    (string)($issue['key'] ?? 'production_issue'),
                    'production_readiness',
                    (string)($issue['message'] ?? 'Production readiness issue.'),
                    $issue
                );
            }
        } catch (Throwable $e) {
            $checks[] = $this->checkItem('production_checker', false, 'ProductionSecurityChecker result', $e->getMessage());
            $this->issue('critical', 'production_checker_failed', 'production_readiness', 'Production checker failed: ' . $e->getMessage());
        }
        $this->section('production_readiness', 'Production Readiness', $checks, $issuesBefore);
    }

    private function checkStoragePaths(): void
    {
        $checks = [];
        $issuesBefore = count($this->issues);
        $paths = is_array($this->config['paths'] ?? null) ? $this->config['paths'] : [];
        $directoryKeys = ['private_storage', 'quarantine', 'cache', 'logs', 'audit', 'backups'];

        foreach ($directoryKeys as $key) {
            $path = $this->resolvePath((string)($paths[$key] ?? ''));
            $exists = $path !== '' && is_dir($path);
            $parent = $path !== '' ? dirname($path) : '';
            $canCreate = !$exists && $parent !== '' && is_dir($parent) && is_writable($parent);
            $writable = $exists && is_writable($path);
            $ok = $exists ? $writable : $canCreate;
            $checks[] = $this->checkItem('path_' . $key, $ok, $key . ' storage path', $exists ? ($writable ? 'exists and writable' : 'exists but not writable') : ($canCreate ? 'missing but parent writable' : 'missing and parent not writable'));

            if ($path === '') {
                $this->issue('high', 'path_' . $key . '_empty', 'storage_paths', $key . ' path is empty.');
                continue;
            }
            if ($this->looksPublic($path)) {
                $this->issue('high', 'path_' . $key . '_public', 'storage_paths', $key . ' should not be inside a public web folder.', ['path' => $path]);
            }
            if (!$ok) {
                $this->issue('high', 'path_' . $key . '_not_writable', 'storage_paths', $key . ' path must exist and be writable, or its parent must be writable.', ['path' => $path]);
            }
        }

        $tokenPath = $this->resolvePath((string)($paths['tokens'] ?? ''));
        $tokenParent = $tokenPath !== '' ? dirname($tokenPath) : '';
        $tokenOk = $tokenPath !== '' && ((is_file($tokenPath) && is_writable($tokenPath)) || (!is_file($tokenPath) && is_dir($tokenParent) && is_writable($tokenParent)));
        $checks[] = $this->checkItem('path_tokens', $tokenOk, 'token store file path', $tokenOk ? 'writable or creatable' : 'not writable/creatable');
        if (!$tokenOk) {
            $this->issue('high', 'token_store_file_not_writable', 'storage_paths', 'Token store file must be writable or creatable by the PHP process.', ['path' => $tokenPath]);
        }
        if ($tokenPath !== '' && $this->looksPublic($tokenPath)) {
            $this->issue('high', 'token_store_file_public', 'storage_paths', 'Token store file should not be inside a public web folder.', ['path' => $tokenPath]);
        }

        $this->section('storage_paths', 'Storage Paths and Permissions', $checks, $issuesBefore);
    }

    private function checkStorageDrivers(): void
    {
        $checks = [];
        $issuesBefore = count($this->issues);
        foreach (['cache', 'rate_limiter', 'token_store'] as $section) {
            $driver = strtolower(trim((string)($this->config[$section]['driver'] ?? 'file')));
            $valid = in_array($driver, ['file', 'redis', 'database'], true);
            $checks[] = $this->checkItem($section . '_driver', $valid, $section . ' driver', $driver === '' ? 'empty' : $driver);
            if (!$valid) {
                $this->issue('high', $section . '_driver_invalid', 'storage_drivers', $section . ' driver must be one of file, redis, or database.', ['driver' => $driver]);
                continue;
            }
            if ($driver === 'redis' && !extension_loaded('redis')) {
                $this->issue('medium', $section . '_redis_extension_missing', 'storage_drivers', $section . ' is configured for Redis, but ext-redis is not loaded. Inject a compatible client or install ext-redis.', ['driver' => $driver]);
            }
            if ($driver === 'database') {
                $dbDriver = strtolower((string)($this->config['database']['driver'] ?? ''));
                if (!in_array($dbDriver, ['mysql', 'mariadb'], true)) {
                    $this->issue('high', $section . '_database_driver_not_mysql', 'storage_drivers', $section . ' database store currently requires MySQL/MariaDB SQL semantics.', ['database_driver' => $dbDriver]);
                }
            }
        }
        $this->section('storage_drivers', 'Storage Drivers', $checks, $issuesBefore);
    }

    private function checkSecurityHeaders(): void
    {
        $checks = [];
        $issuesBefore = count($this->issues);
        $headersConfig = is_array($this->config['security_headers'] ?? null) ? $this->config['security_headers'] : [];
        $enabled = !array_key_exists('enabled', $headersConfig) || $headersConfig['enabled'] !== false;
        $checks[] = $this->checkItem('security_headers_enabled', $enabled, 'Security headers enabled', $enabled ? 'enabled' : 'disabled');
        if (!$enabled) {
            $this->issue('high', 'security_headers_disabled', 'security_headers', 'Security headers middleware is disabled.');
        }

        try {
            $httpsRequest = new Request('GET', '/', [], [], [], ['HTTPS' => 'on', 'HTTP_HOST' => 'localhost', 'REMOTE_ADDR' => '127.0.0.1']);
            $headers = (new SecurityHeadersBuilder($headersConfig))->headers('doctor-nonce', $httpsRequest);
            foreach (['X-Content-Type-Options', 'Referrer-Policy', 'Content-Security-Policy', 'Permissions-Policy'] as $name) {
                $exists = isset($headers[$name]);
                $checks[] = $this->checkItem('header_' . strtolower(str_replace('-', '_', $name)), $exists, $name . ' header', $exists ? 'present' : 'missing');
                if (!$exists && $enabled) {
                    $level = $name === 'Content-Security-Policy' ? 'medium' : 'low';
                    $this->issue($level, 'header_' . strtolower(str_replace('-', '_', $name)) . '_missing', 'security_headers', $name . ' is not emitted by current security header config.');
                }
            }

            $hstsEnabled = isset($headers['Strict-Transport-Security']);
            $checks[] = $this->checkItem('header_hsts', $hstsEnabled, 'Strict-Transport-Security header on HTTPS', $hstsEnabled ? $headers['Strict-Transport-Security'] : 'not emitted');
            if (($this->config['app']['env'] ?? 'local') === 'production' && !empty($this->config['app']['force_https']) && !$hstsEnabled) {
                $this->issue('medium', 'hsts_not_emitted_for_https', 'security_headers', 'HSTS should be emitted on HTTPS responses after production HTTPS is stable.');
            }
        } catch (Throwable $e) {
            $checks[] = $this->checkItem('security_headers_build', false, 'Build security headers', $e->getMessage());
            $this->issue('high', 'security_headers_build_failed', 'security_headers', 'Security headers could not be built: ' . $e->getMessage());
        }
        $this->section('security_headers', 'Security Headers', $checks, $issuesBefore);
    }

    private function checkUploadScanner(): void
    {
        $checks = [];
        $issuesBefore = count($this->issues);
        $scanner = is_array($this->config['uploads']['scanner'] ?? null) ? $this->config['uploads']['scanner'] : [];
        $driver = strtolower((string)($scanner['driver'] ?? 'heuristic'));
        $valid = in_array($driver, ['none', 'heuristic', 'clamav', 'composite'], true);
        $checks[] = $this->checkItem('upload_scanner_driver', $valid, 'Upload scanner driver', $driver);
        if (!$valid) {
            $this->issue('high', 'upload_scanner_driver_invalid', 'upload_scanner', 'Upload scanner driver must be one of none, heuristic, clamav, or composite.', ['driver' => $driver]);
        }

        if (($this->config['app']['env'] ?? 'local') === 'production' && $driver === 'none') {
            $this->issue('medium', 'upload_scanner_disabled_in_production', 'upload_scanner', 'Production uploads should use at least heuristic scanning.');
        }

        if (in_array($driver, ['clamav', 'composite'], true)) {
            $binary = (string)($scanner['clamav_binary'] ?? 'clamscan');
            $binaryPath = $this->findExecutable($binary);
            $found = $binaryPath !== null;
            $checks[] = $this->checkItem('clamav_binary', $found, 'ClamAV binary available', $found ? $binaryPath : $binary . ' not found');
            if (!$found) {
                $level = !empty($scanner['fail_closed']) ? 'medium' : 'high';
                $this->issue($level, 'clamav_binary_not_found', 'upload_scanner', 'ClamAV scanner binary was not found in PATH or configured path.', ['binary' => $binary, 'fail_closed' => (bool)($scanner['fail_closed'] ?? false)]);
            }
            if (empty($scanner['fail_closed']) && ($this->config['app']['env'] ?? 'local') === 'production') {
                $this->issue('high', 'clamav_fail_open_in_production', 'upload_scanner', 'Production ClamAV/composite upload scanning should fail closed.');
            }
        }

        $this->section('upload_scanner', 'Upload Scanner', $checks, $issuesBefore);
    }

    private function checkPublicPackage(): void
    {
        $checks = [];
        $issuesBefore = count($this->issues);

        $requiredFiles = [
            'composer.json' => 'Composer metadata',
            'README.md' => 'README',
            'LICENSE' => 'License file',
            'CHANGELOG.md' => 'Changelog',
            'SECURITY.md' => 'Security policy',
            '.gitattributes' => 'Release export rules',
            '.github/workflows/ci.yml' => 'GitHub CI workflow',
            'bin/mnb-secure' => 'CLI binary',
        ];
        foreach ($requiredFiles as $relative => $label) {
            $exists = is_file($this->projectRoot . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $relative));
            $checks[] = $this->checkItem('package_' . str_replace(['/', '.', '-'], '_', $relative), $exists, $label, $exists ? 'present' : 'missing');
            if (!$exists) {
                $this->issue('medium', 'package_file_missing_' . str_replace(['/', '.', '-'], '_', $relative), 'public_package', $label . ' is missing from the public package.', ['file' => $relative]);
            }
        }

        $composerPath = $this->projectRoot . DIRECTORY_SEPARATOR . 'composer.json';
        if (is_file($composerPath)) {
            $composer = json_decode((string)file_get_contents($composerPath), true);
            $validJson = is_array($composer);
            $checks[] = $this->checkItem('composer_json_valid', $validJson, 'composer.json parses as JSON', $validJson ? 'valid' : 'invalid');
            if (!$validJson) {
                $this->issue('high', 'composer_json_invalid', 'public_package', 'composer.json is not valid JSON.');
            } else {
                $license = (string)($composer['license'] ?? '');
                $licenseOk = $license !== '' && strtolower($license) !== 'proprietary';
                $checks[] = $this->checkItem('composer_license', $licenseOk, 'Composer license is public-use friendly', $license ?: 'missing');
                if (!$licenseOk) {
                    $this->issue('high', 'composer_license_not_public', 'public_package', 'Composer license should not be proprietary for a public-use GitHub library.', ['license' => $license]);
                }
                if (array_key_exists('version', $composer)) {
                    $this->issue('low', 'composer_inline_version_present', 'public_package', 'Prefer Git tags over an inline Composer version field.');
                }
                foreach (['ext-openssl', 'ext-fileinfo', 'ext-json', 'ext-pdo'] as $requirement) {
                    $declared = isset($composer['require'][$requirement]);
                    $checks[] = $this->checkItem('composer_requires_' . str_replace('-', '_', $requirement), $declared, 'Composer declares ' . $requirement, $declared ? 'declared' : 'missing');
                    if (!$declared) {
                        $this->issue('medium', 'composer_missing_' . str_replace('-', '_', $requirement), 'public_package', 'composer.json should declare required extension ' . $requirement . '.');
                    }
                }
            }
        }

        $binPath = $this->projectRoot . DIRECTORY_SEPARATOR . 'bin' . DIRECTORY_SEPARATOR . 'mnb-secure';
        if (is_file($binPath)) {
            $executable = is_executable($binPath);
            $checks[] = $this->checkItem('cli_binary_executable', $executable, 'CLI binary executable bit', $executable ? 'executable' : 'not executable');
            if (!$executable) {
                $this->issue('medium', 'cli_binary_not_executable', 'public_package', 'bin/mnb-secure should be executable for Unix/macOS users.');
            }
        }

        $nestedDuplicate = is_dir($this->projectRoot . DIRECTORY_SEPARATOR . 'mnb-secure-core' . DIRECTORY_SEPARATOR . 'src');
        $checks[] = $this->checkItem('no_nested_duplicate_project', !$nestedDuplicate, 'No nested duplicate project directory', $nestedDuplicate ? 'duplicate found' : 'clean');
        if ($nestedDuplicate) {
            $this->issue('high', 'nested_duplicate_project_found', 'public_package', 'Release archive appears to contain a nested mnb-secure-core project copy.');
        }

        $this->section('public_package', 'Public Package Readiness', $checks, $issuesBefore);
    }

    private function checkSecrets(): void
    {
        $checks = [];
        $issuesBefore = count($this->issues);
        try {
            $kernel = new SecurityKernel($this->config);
            $inventory = $kernel->secretHealthReport()->toArray();
            $checks[] = $this->checkItem('secret_inventory', (bool)($inventory['passed'] ?? false), 'Secret inventory', ($inventory['summary']['present'] ?? 0) . '/' . ($inventory['summary']['total'] ?? 0) . ' present');
            foreach ((array)($inventory['items'] ?? []) as $item) {
                if (($item['severity'] ?? '') === 'high') {
                    $this->issue('high', 'secret_inventory_issue', 'secret_scan', 'Secret inventory issue: ' . (string)($item['name'] ?? 'unknown'), $item);
                }
            }
            $rotation = $kernel->secretRotationReport()->toArray();
            $checks[] = $this->checkItem('secret_rotation', (bool)($rotation['passed'] ?? false), 'Secret rotation metadata', (bool)($rotation['passed'] ?? false) ? 'ok' : 'attention required');
        } catch (Throwable $e) {
            $checks[] = $this->checkItem('secret_inventory', false, 'Secret inventory', $e->getMessage());
            $this->issue('medium', 'secret_inventory_failed', 'secret_scan', 'Secret inventory check failed: ' . $e->getMessage());
        }
        try {
            $scannerPolicy = is_array($this->config['secrets']['scanning'] ?? null) ? $this->config['secrets']['scanning'] : [];
            $scanner = new SecretScanner($scannerPolicy);
            $findings = $scanner->scanDirectory($this->projectRoot);
            $clean = count($findings) === 0;
            $checks[] = $this->checkItem('secret_scan', $clean, 'Secret scanner', $clean ? 'no findings' : count($findings) . ' finding(s)');
            foreach ($findings as $finding) {
                $level = (string)($finding['severity'] ?? 'high');
                $this->issue(in_array($level, ['critical', 'high', 'medium', 'low'], true) ? $level : 'high', 'secret_scanner_finding', 'secret_scan', 'Potential secret found in project tree.', is_array($finding) ? $finding : ['finding' => $finding]);
            }
        } catch (Throwable $e) {
            $checks[] = $this->checkItem('secret_scan', false, 'Secret scanner', $e->getMessage());
            $this->issue('medium', 'secret_scan_failed', 'secret_scan', 'Secret scanner failed: ' . $e->getMessage());
        }
        $this->section('secret_scan', 'Secret Scan and Inventory', $checks, $issuesBefore);
    }


    private function checkVulnerabilityCoverage(): void
    {
        $checks = [];
        $issuesBefore = count($this->issues);
        try {
            $kernel = new SecurityKernel($this->config);
            $report = $kernel->vulnerabilityCoverageReport()->toArray();
            $score = (float)($report['overall_score'] ?? 0);
            $checks[] = $this->checkItem('vulnerability_coverage_score', !empty($report['passed']), 'Vulnerability coverage score', $score . ' / 100, grade ' . (string)($report['grade'] ?? 'n/a'));
            $checks[] = $this->checkItem('vulnerability_matrix_rows', (int)($report['count'] ?? 0) >= 20, 'Vulnerability matrix rows', (int)($report['count'] ?? 0));
            foreach ((array)($report['needs_attention'] ?? []) as $row) {
                $severity = (string)($row['severity'] ?? 'medium');
                $level = in_array($severity, ['critical','high'], true) ? 'medium' : 'low';
                $this->issue($level, 'vulnerability_attention_' . (string)($row['id'] ?? 'unknown'), 'vulnerability_matrix', (string)($row['name'] ?? 'Vulnerability') . ' is ' . (string)($row['status'] ?? 'unknown') . '.', $row);
            }
        } catch (Throwable $e) {
            $checks[] = $this->checkItem('vulnerability_coverage_score', false, 'Vulnerability coverage score', $e->getMessage());
            $this->issue('medium', 'vulnerability_matrix_failed', 'vulnerability_matrix', 'Vulnerability matrix check failed: ' . $e->getMessage());
        }
        $this->section('vulnerability_matrix', 'Vulnerability Blocking Matrix', $checks, $issuesBefore);
    }

    /** @param array<int,array<string,mixed>> $checks */
    private function section(string $key, string $title, array $checks, int $issuesBefore): void
    {
        $sectionIssues = array_values(array_filter($this->issues, fn(array $issue): bool => ($issue['section'] ?? '') === $key));
        $counts = $this->countByLevel($sectionIssues);
        $this->sections[$key] = [
            'title' => $title,
            'passed' => (($counts['critical'] ?? 0) + ($counts['high'] ?? 0)) === 0,
            'checks' => $checks,
            'issues' => $sectionIssues,
            'issue_counts' => $counts,
            'new_issues' => max(0, count($this->issues) - $issuesBefore),
        ];
    }

    /** @return array<string,mixed> */
    private function checkItem(string $key, bool $passed, string $label, mixed $value = null): array
    {
        return ['key' => $key, 'passed' => $passed, 'label' => $label, 'value' => $value];
    }

    /** @param array<string,mixed> $context */
    private function issue(string $level, string $key, string $section, string $message, array $context = []): void
    {
        $this->issues[] = [
            'level' => $this->normalizeLevel($level),
            'key' => $key,
            'section' => $section,
            'message' => $message,
            'context' => $this->redact($context),
        ];
    }

    private function normalizeLevel(string $level): string
    {
        $level = strtolower(trim($level));
        return in_array($level, ['critical', 'high', 'medium', 'low', 'info'], true) ? $level : 'medium';
    }

    /** @param array<int,array<string,mixed>> $issues @return array<string,int> */
    private function countByLevel(array $issues): array
    {
        $counts = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0, 'info' => 0];
        foreach ($issues as $issue) {
            $level = $this->normalizeLevel((string)($issue['level'] ?? 'medium'));
            $counts[$level]++;
        }
        return $counts;
    }

    private function extensionIsUseful(string $extension): bool
    {
        if ($extension === 'redis') {
            foreach (['cache', 'rate_limiter', 'token_store'] as $section) {
                if (strtolower((string)($this->config[$section]['driver'] ?? 'file')) === 'redis') {
                    return true;
                }
            }
            return false;
        }
        if ($extension === 'zip') {
            $uploads = $this->config['uploads'] ?? [];
            if (!is_array($uploads)) {
                return false;
            }
            $profile = strtolower((string)($uploads['profile'] ?? 'custom'));
            if ($profile === 'archives') {
                return true;
            }
            return !empty($uploads['allowed_extensions']) && in_array('zip', array_map('strtolower', (array)$uploads['allowed_extensions']), true);
        }
        return false;
    }

    private function functionAllowed(string $function): bool
    {
        $disabled = array_filter(array_map('trim', explode(',', (string)ini_get('disable_functions'))));
        return !in_array($function, $disabled, true);
    }

    private function resolvePath(string $path): string
    {
        $path = trim($path);
        if ($path === '') {
            return '';
        }
        if ($this->isAbsolutePath($path)) {
            return $path;
        }
        return $this->projectRoot . DIRECTORY_SEPARATOR . $path;
    }

    private function isAbsolutePath(string $path): bool
    {
        if (str_starts_with($path, '/')) {
            return true;
        }

        return strlen($path) >= 3
            && ctype_alpha($path[0])
            && $path[1] === ':'
            && ($path[2] === '\\' || $path[2] === '/');
    }

    private function looksPublic(string $path): bool
    {
        $normalized = str_replace('\\', '/', $path);
        return str_contains($normalized, '/public/')
            || str_ends_with($normalized, '/public')
            || str_contains($normalized, '/htdocs/')
            || str_contains($normalized, '/www/');
    }

    private function findExecutable(string $binary): ?string
    {
        $binary = trim($binary);
        if ($binary === '') {
            return null;
        }
        if (str_contains($binary, '/') || str_contains($binary, '\\')) {
            return is_file($binary) && is_executable($binary) ? $binary : null;
        }
        $path = (string)getenv('PATH');
        foreach (explode(PATH_SEPARATOR, $path) as $dir) {
            $candidate = rtrim($dir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $binary;
            if (is_file($candidate) && is_executable($candidate)) {
                return $candidate;
            }
        }
        return null;
    }

    private function redact(mixed $value): mixed
    {
        if (is_array($value)) {
            $redacted = [];
            foreach ($value as $key => $item) {
                $keyString = is_string($key) ? strtolower($key) : (string)$key;
                if (preg_match('/(password|secret|token|api[_-]?key|authorization|private[_-]?key)/i', $keyString)) {
                    $redacted[$key] = '[redacted]';
                } else {
                    $redacted[$key] = $this->redact($item);
                }
            }
            return $redacted;
        }
        if (is_string($value) && preg_match('/(password|secret|token|api[_-]?key)=/i', $value)) {
            return '[redacted]';
        }
        return $value;
    }
}
