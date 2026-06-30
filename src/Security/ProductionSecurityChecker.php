<?php
namespace Mnb\SecurityCore\Security;

class ProductionSecurityChecker
{
    public function __construct(private array $config, private ?string $projectRoot = null)
    {
        $this->projectRoot ??= dirname(__DIR__, 2);
    }

    public function check(): array
    {
        $issues = [];
        $app = $this->config['app'] ?? [];
        $cookies = $this->config['cookies'] ?? [];
        $paths = $this->config['paths'] ?? [];
        $errors = $this->config['errors'] ?? [];
        $originProtection = $this->config['origin_protection'] ?? [];
        $uploads = $this->config['uploads'] ?? [];

        if (($app['env'] ?? 'local') === 'production' && !empty($app['debug'])) {
            $issues[] = ['level' => 'critical', 'key' => 'debug_enabled', 'message' => 'APP_DEBUG must be false in production.'];
        }
        if (($app['env'] ?? 'local') === 'production' && array_key_exists('hide_frontend_errors', $errors) && empty($errors['hide_frontend_errors'])) {
            $issues[] = ['level' => 'critical', 'key' => 'frontend_errors_not_hidden', 'message' => 'Raw frontend errors must be hidden in production.'];
        }
        if (($app['env'] ?? 'local') === 'production' && empty($app['force_https'])) {
            $issues[] = ['level' => 'critical', 'key' => 'https_not_forced', 'message' => 'HTTPS must be forced in production.'];
        }
        if (strlen((string)($app['key'] ?? '')) < 32) {
            $issues[] = ['level' => 'critical', 'key' => 'weak_app_key', 'message' => 'APP_KEY must be at least 32 characters.'];
        }
        if (($app['env'] ?? 'local') === 'production' && empty($cookies['secure'])) {
            $issues[] = ['level' => 'high', 'key' => 'insecure_cookie', 'message' => 'Secure cookie flag should be enabled in production.'];
        }
        if (empty($cookies['http_only'])) {
            $issues[] = ['level' => 'high', 'key' => 'httponly_disabled', 'message' => 'HttpOnly cookie flag should be enabled.'];
        }
        if (empty($app['trusted_hosts'])) {
            $issues[] = ['level' => 'medium', 'key' => 'trusted_hosts_empty', 'message' => 'Trusted hosts list is empty.'];
        }
        foreach ((array)($app['trusted_hosts'] ?? []) as $trustedHost) {
            if (ServerIdentityHider::isIpAddressHost((string)$trustedHost)) {
                $issues[] = ['level' => 'medium', 'key' => 'trusted_host_is_ip', 'message' => 'Trusted hosts should prefer public domains, not direct server IP addresses.'];
                break;
            }
        }
        if (($app['env'] ?? 'local') === 'production') {
            if (empty($originProtection['enabled'])) {
                $issues[] = ['level' => 'medium', 'key' => 'origin_protection_disabled', 'message' => 'Origin/server identity protection should be enabled in production.'];
            }
            if (empty($originProtection['block_direct_ip_host'])) {
                $issues[] = ['level' => 'high', 'key' => 'direct_ip_host_allowed', 'message' => 'Direct IP Host requests should be blocked in production.'];
            }
            if (!empty($originProtection['require_cdn_or_proxy_in_production']) && empty($originProtection['cdn_or_proxy_enabled'])) {
                $issues[] = ['level' => 'medium', 'key' => 'cdn_or_proxy_not_marked_enabled', 'message' => 'Use a CDN/reverse proxy plus firewall rules to truly hide the origin server IP.'];
            }
        }
        if (($app['env'] ?? 'local') === 'production' && (($uploads['scanner']['driver'] ?? 'heuristic') === 'none')) {
            $issues[] = ['level' => 'medium', 'key' => 'upload_scanner_disabled', 'message' => 'Enable at least heuristic upload scanning in production.'];
        }
        if (($app['env'] ?? 'local') === 'production') {
            $scannerDriver = (string)($uploads['scanner']['driver'] ?? 'heuristic');
            $usesExternalScanner = in_array($scannerDriver, ['clamav', 'composite'], true);
            if ($usesExternalScanner && empty($uploads['scanner']['fail_closed'])) {
                $issues[] = ['level' => 'high', 'key' => 'upload_scanner_fail_open', 'message' => 'Production ClamAV/composite upload scanning should fail closed when the scanner is unavailable.'];
            }
        }
        if (!empty($uploads['allowed_extensions']) && array_intersect((array)$uploads['allowed_extensions'], ['php', 'phtml', 'phar', 'exe', 'sh'])) {
            $issues[] = ['level' => 'critical', 'key' => 'executable_upload_extension_allowed', 'message' => 'Executable upload extensions must not be allowed.'];
        }
        foreach (['private_storage', 'backups', 'logs', 'audit'] as $key) {
            if (!empty($paths[$key]) && $this->looksPublic((string)$paths[$key])) {
                $issues[] = ['level' => 'high', 'key' => $key . '_public', 'message' => $key . ' should not be inside a public web folder.'];
            }
        }
        return [
            'passed' => count(array_filter($issues, fn($i) => in_array($i['level'], ['critical', 'high'], true))) === 0,
            'issues' => $issues,
        ];
    }

    private function looksPublic(string $path): bool
    {
        $normalized = str_replace('\\', '/', $path);
        return str_contains($normalized, '/public/') || str_ends_with($normalized, '/public') || str_contains($normalized, '/htdocs/') || str_contains($normalized, '/www/');
    }
}
