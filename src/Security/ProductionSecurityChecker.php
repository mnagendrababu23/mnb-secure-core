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
        $audit = $this->config['audit'] ?? [];
        $securityHeaders = $this->config['security_headers'] ?? [];
        $cors = $this->config['cors'] ?? [];
        $requestValidation = $this->config['request_validation'] ?? [];
        $requestReceiving = $this->config['request_receiving'] ?? [];
        $authentication = $this->config['authentication'] ?? [];
        $authorization = $this->config['authorization'] ?? [];
        $trustBoundaries = $this->config['trust_boundaries'] ?? [];
        $dataProtection = $this->config['data_protection'] ?? [];
        $webSecurity = $this->config['web_security'] ?? [];
        $fileSecurity = $this->config['file_security'] ?? [];

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
        if (($app['env'] ?? 'local') === 'production' && array_key_exists('enabled', $audit) && empty($audit['enabled'])) {
            $issues[] = ['level' => 'high', 'key' => 'audit_logging_disabled', 'message' => 'Structured audit logging should stay enabled in production for auth, token, upload, admin, database, and sensitive actions.'];
        }
        if (($app['env'] ?? 'local') === 'production') {
            if (is_array($cors)) {
                $origins = is_array($cors['allowed_origins'] ?? null) ? $cors['allowed_origins'] : [];
                if (in_array('*', $origins, true)) {
                    $issues[] = ['level' => !empty($cors['allow_credentials']) ? 'high' : 'medium', 'key' => 'wildcard_cors_origin', 'message' => 'Production CORS should use explicit allowed origins; wildcard origins are risky and cannot be combined with credentials.'];
                }
                if (!empty($cors['allow_credentials']) && in_array('*', $origins, true)) {
                    $issues[] = ['level' => 'high', 'key' => 'cors_credentials_with_wildcard', 'message' => 'CORS allow_credentials=true must not be used with wildcard allowed_origins.'];
                }
            }
            if (array_key_exists('enabled', $securityHeaders) && empty($securityHeaders['enabled'])) {
                $issues[] = ['level' => 'high', 'key' => 'security_headers_disabled', 'message' => 'Security response headers should be enabled in production.'];
            }
            $hsts = $securityHeaders['hsts'] ?? false;
            $hstsEnabled = is_bool($hsts) ? $hsts : (is_array($hsts) ? !empty($hsts['enabled']) : false);
            if (!empty($app['force_https']) && !$hstsEnabled) {
                $issues[] = ['level' => 'medium', 'key' => 'hsts_disabled', 'message' => 'Enable HSTS after HTTPS is stable so browsers remember to use HTTPS.'];
            }
            $csp = $securityHeaders['csp'] ?? true;
            $cspEnabled = is_bool($csp) ? $csp : (is_array($csp) ? (!array_key_exists('enabled', $csp) || !empty($csp['enabled'])) : true);
            if (!$cspEnabled) {
                $issues[] = ['level' => 'medium', 'key' => 'csp_disabled', 'message' => 'Content-Security-Policy should be enabled in production.'];
            }
            if (is_array($csp) && !empty($csp['directives']['script-src']) && empty($csp['report_only'])) {
                $scriptSrc = is_array($csp['directives']['script-src']) ? $csp['directives']['script-src'] : preg_split('/\s+/', (string)$csp['directives']['script-src']);
                if (in_array("'unsafe-inline'", $scriptSrc ?: [], true)) {
                    $issues[] = ['level' => 'medium', 'key' => 'csp_unsafe_inline_scripts', 'message' => 'Production enforcing CSP should avoid script-src unsafe-inline. Prefer nonce or hash based scripts.'];
                }
            }
            $permissions = $securityHeaders['permissions_policy'] ?? ['preset' => 'strict'];
            $preset = is_array($permissions) ? strtolower((string)($permissions['preset'] ?? 'strict')) : strtolower((string)$permissions);
            if (in_array($preset, ['none', 'disabled', 'off'], true)) {
                $issues[] = ['level' => 'medium', 'key' => 'permissions_policy_disabled', 'message' => 'Permissions-Policy should restrict browser features in production.'];
            }
            if (is_array($requestValidation)) {
                if (array_key_exists('enabled', $requestValidation) && empty($requestValidation['enabled'])) {
                    $issues[] = ['level' => 'high', 'key' => 'request_validation_disabled', 'message' => 'Request input validation should be enabled in production before controller/business logic runs.'];
                }
                if (array_key_exists('sanitize', $requestValidation) && empty($requestValidation['sanitize'])) {
                    $issues[] = ['level' => 'medium', 'key' => 'request_sanitization_disabled', 'message' => 'Request input sanitization should be enabled in production for safe normalization and blocked key removal.'];
                }
                if (empty($requestValidation['default']) && empty($requestValidation['routes'])) {
                    $issues[] = ['level' => 'medium', 'key' => 'request_validation_no_policies', 'message' => 'Define default or route-specific request validation policies for public write endpoints.'];
                }
            }
            if (is_array($authentication)) {
                if (array_key_exists('enabled', $authentication) && empty($authentication['enabled'])) {
                    $issues[] = ['level' => 'high', 'key' => 'authentication_disabled', 'message' => 'Authentication strategies should be enabled in production for protected API, admin, session, webhook, and internal routes.'];
                }
                if (empty($authentication['strategies']) || !is_array($authentication['strategies'])) {
                    $issues[] = ['level' => 'high', 'key' => 'authentication_strategies_missing', 'message' => 'Define named authentication strategies such as api_bearer, admin_bearer, web_session, webhook_hmac, and internal_system.'];
                } else {
                    foreach ($authentication['strategies'] as $strategyName => $strategy) {
                        if (!is_array($strategy)) { continue; }
                        if (str_contains((string)$strategyName, 'admin') && (empty($strategy['required']) || (($strategy['type'] ?? 'bearer') === 'none'))) {
                            $issues[] = ['level' => 'high', 'key' => 'admin_authentication_strategy_not_required', 'message' => 'Admin authentication strategy ' . (string)$strategyName . ' must require credentials.'];
                        }
                        if (($strategy['type'] ?? null) === 'signature') {
                            $signature = is_array($strategy['signature'] ?? null) ? $strategy['signature'] : (is_array($requestReceiving['webhook'] ?? null) ? $requestReceiving['webhook'] : []);
                            if (empty($signature['secret'])) {
                                $issues[] = ['level' => 'high', 'key' => 'signature_authentication_secret_missing', 'message' => 'Signature authentication strategy ' . (string)$strategyName . ' requires a webhook/signature secret.'];
                            }
                        }
                    }
                }
                $passwordPolicy = is_array($authentication['password_policy'] ?? null) ? $authentication['password_policy'] : [];
                if ((int)($passwordPolicy['min_length'] ?? 0) < 12) {
                    $issues[] = ['level' => 'medium', 'key' => 'password_policy_min_length_low', 'message' => 'Production password policy should require at least 12 characters.'];
                }
            }
            if (is_array($authorization)) {
                if (array_key_exists('enabled', $authorization) && empty($authorization['enabled'])) {
                    $issues[] = ['level' => 'high', 'key' => 'authorization_disabled', 'message' => 'Authorization strategy enforcement should be enabled in production for protected resources.'];
                }
                if (array_key_exists('deny_by_default', $authorization) && empty($authorization['deny_by_default'])) {
                    $issues[] = ['level' => 'high', 'key' => 'authorization_not_deny_by_default', 'message' => 'Authorization should be deny-by-default in production.'];
                }
                if (empty($authorization['policies']) || !is_array($authorization['policies'])) {
                    $issues[] = ['level' => 'high', 'key' => 'authorization_policies_missing', 'message' => 'Define authorization policies for protected actions, resources, tenant scope, and field access.'];
                } else {
                    foreach ($authorization['policies'] as $policyName => $policy) {
                        if (!is_array($policy)) { continue; }
                        if (str_contains((string)$policyName, 'delete') && empty($policy['audit'])) {
                            $issues[] = ['level' => 'medium', 'key' => 'destructive_authorization_policy_not_audited', 'message' => 'Destructive authorization policy ' . (string)$policyName . ' should enable audit logging.'];
                        }
                        if (!empty($policy['tenant_required']) && empty($policy['resource'])) {
                            $issues[] = ['level' => 'medium', 'key' => 'tenant_authorization_policy_without_resource', 'message' => 'Tenant-required authorization policy ' . (string)$policyName . ' should declare a resource.'];
                        }
                    }
                }
            }
            if (is_array($requestReceiving)) {
                if (array_key_exists('enabled', $requestReceiving) && empty($requestReceiving['enabled'])) {
                    $issues[] = ['level' => 'high', 'key' => 'request_receiving_disabled', 'message' => 'Secure request receiving profiles should be enabled in production.'];
                }
                if (empty($requestReceiving['profiles']) || !is_array($requestReceiving['profiles'])) {
                    $issues[] = ['level' => 'medium', 'key' => 'request_receiving_profiles_missing', 'message' => 'Define named request receiving profiles for public, authenticated API, upload, admin, webhook, and internal routes.'];
                }
                $webhookProfile = $requestReceiving['profiles']['webhook'] ?? null;
                $webhookConfig = is_array($requestReceiving['webhook'] ?? null) ? $requestReceiving['webhook'] : [];
                if (is_array($webhookProfile) && (($webhookProfile['auth'] ?? null) === 'signature') && empty($webhookConfig['secret'])) {
                    $issues[] = ['level' => 'high', 'key' => 'webhook_secret_missing', 'message' => 'Webhook receiving profile uses signature auth but WEBHOOK_SECRET is missing.'];
                }
                foreach ((array)($requestReceiving['profiles'] ?? []) as $profileName => $profile) {
                    if (!is_array($profile)) {
                        continue;
                    }
                    if (!empty($profile['content_types']) && empty($profile['methods'])) {
                        $issues[] = ['level' => 'medium', 'key' => 'request_receiving_profile_missing_methods', 'message' => 'Request receiving profile ' . (string)$profileName . ' should declare allowed HTTP methods.'];
                    }
                    if (($profile['auth'] ?? null) === null && empty($profile['auth_strategy']) && str_contains((string)$profileName, 'admin')) {
                        $issues[] = ['level' => 'high', 'key' => 'admin_receiving_profile_without_auth', 'message' => 'Admin request receiving profiles should require auth or an auth_strategy.'];
                    }
                }
            }

            if (is_array($dataProtection)) {
                if (array_key_exists('enabled', $dataProtection) && empty($dataProtection['enabled'])) {
                    $issues[] = ['level' => 'high', 'key' => 'data_protection_disabled', 'message' => 'Data protection strategy should be enabled in production to enforce classification, encryption, masking, export, and storage controls.'];
                }
                if (array_key_exists('deny_unclassified_fields', $dataProtection) && empty($dataProtection['deny_unclassified_fields'])) {
                    $issues[] = ['level' => 'medium', 'key' => 'data_protection_allows_unclassified_fields', 'message' => 'Production data protection should deny or explicitly classify sensitive resource fields.'];
                }
                $encryption = is_array($dataProtection['encryption'] ?? null) ? $dataProtection['encryption'] : [];
                if (array_key_exists('enabled', $encryption) && empty($encryption['enabled'])) {
                    $issues[] = ['level' => 'high', 'key' => 'data_encryption_disabled', 'message' => 'Data encryption should be enabled in production for confidential and sensitive protected fields.'];
                }
                if (!empty($encryption['enabled'])) {
                    $keys = is_array($encryption['keys'] ?? null) ? $encryption['keys'] : [];
                    $current = (string)($encryption['current_key_id'] ?? '');
                    if ($keys === [] || $current === '' || !array_key_exists($current, $keys) || strlen((string)($keys[$current] ?? '')) < 32) {
                        $issues[] = ['level' => 'high', 'key' => 'data_encryption_key_not_ready', 'message' => 'Data encryption requires a current key id mapped to a 32+ character key in production.'];
                    }
                }
                if (empty($dataProtection['resources']) || !is_array($dataProtection['resources'])) {
                    $issues[] = ['level' => 'medium', 'key' => 'data_protection_resources_missing', 'message' => 'Define data protection resource policies for sensitive database records, files, exports, logs, and backups.'];
                }
                $exports = is_array($dataProtection['exports'] ?? null) ? $dataProtection['exports'] : [];
                if (array_key_exists('csv_injection_protection', $exports) && empty($exports['csv_injection_protection'])) {
                    $issues[] = ['level' => 'medium', 'key' => 'csv_injection_protection_disabled', 'message' => 'CSV export injection protection should stay enabled in production.'];
                }
                $storage = is_array($dataProtection['storage'] ?? null) ? $dataProtection['storage'] : [];
                if (array_key_exists('encrypt_files', $storage) && empty($storage['encrypt_files'])) {
                    $issues[] = ['level' => 'medium', 'key' => 'encrypted_file_storage_disabled', 'message' => 'Consider encrypted private storage for uploaded sensitive files.'];
                }
                $backups = is_array($dataProtection['backups'] ?? null) ? $dataProtection['backups'] : [];
                if (array_key_exists('encrypt', $backups) && empty($backups['encrypt'])) {
                    $issues[] = ['level' => 'medium', 'key' => 'encrypted_backups_disabled', 'message' => 'Production backups should be encrypted because they often contain highly sensitive data.'];
                }
                if (array_key_exists('sign', $backups) && empty($backups['sign'])) {
                    $issues[] = ['level' => 'medium', 'key' => 'backup_signing_disabled', 'message' => 'Production backups should be signed or integrity-protected.'];
                }
                $logs = is_array($dataProtection['logs'] ?? null) ? $dataProtection['logs'] : [];
                if (array_key_exists('redact_before_write', $logs) && empty($logs['redact_before_write'])) {
                    $issues[] = ['level' => 'high', 'key' => 'log_redaction_disabled', 'message' => 'Audit/log redaction should stay enabled before writing production logs.'];
                }
            }

            if (is_array($webSecurity)) {
                if (array_key_exists('enabled', $webSecurity) && empty($webSecurity['enabled'])) {
                    $issues[] = ['level' => 'high', 'key' => 'web_security_disabled', 'message' => 'Web application security controls should be enabled in production for escaping, redirects, cookies, cache-control, and signed URLs.'];
                }
                if (empty($webSecurity['profiles']) || !is_array($webSecurity['profiles'])) {
                    $issues[] = ['level' => 'medium', 'key' => 'web_security_profiles_missing', 'message' => 'Define web security profiles for browser pages, forms, admin panels, JSON APIs, and upload endpoints.'];
                }
                $redirects = is_array($webSecurity['redirects'] ?? null) ? $webSecurity['redirects'] : [];
                if (!empty($redirects['allow_external']) && empty($redirects['allowed_hosts'])) {
                    $issues[] = ['level' => 'high', 'key' => 'external_redirects_without_allowlist', 'message' => 'External redirects in production require an explicit allowed host list.'];
                }
                $webCookies = is_array($webSecurity['cookies'] ?? null) ? $webSecurity['cookies'] : [];
                if (array_key_exists('secure', $webCookies) && empty($webCookies['secure'])) {
                    $issues[] = ['level' => 'high', 'key' => 'web_cookies_not_secure', 'message' => 'Web cookies should default to Secure in production.'];
                }
                if (array_key_exists('http_only', $webCookies) && empty($webCookies['http_only'])) {
                    $issues[] = ['level' => 'medium', 'key' => 'web_cookies_not_httponly', 'message' => 'Web cookies should default to HttpOnly unless the cookie is intentionally readable by JavaScript.'];
                }
                $signed = is_array($webSecurity['signed_urls'] ?? null) ? $webSecurity['signed_urls'] : [];
                if (strlen((string)($signed['key'] ?? '')) < 32) {
                    $issues[] = ['level' => 'high', 'key' => 'signed_url_key_weak', 'message' => 'Signed URL key should be a 32+ character secret in production.'];
                }
                foreach ((array)($webSecurity['profiles'] ?? []) as $profileName => $profile) {
                    if (!is_array($profile)) { continue; }
                    if (str_contains((string)$profileName, 'admin') && (($profile['cache_policy'] ?? '') !== 'sensitive_no_store')) {
                        $issues[] = ['level' => 'medium', 'key' => 'admin_profile_not_no_store', 'message' => 'Admin web security profile ' . (string)$profileName . ' should use sensitive_no_store cache policy.'];
                    }
                    if (!empty($profile['safe_redirects']) && empty($webSecurity['redirects'])) {
                        $issues[] = ['level' => 'medium', 'key' => 'safe_redirects_without_config', 'message' => 'Profile ' . (string)$profileName . ' enables safe redirects but web_security.redirects is not configured.'];
                    }
                }
            }


            if (is_array($fileSecurity)) {
                if (array_key_exists('enabled', $fileSecurity) && empty($fileSecurity['enabled'])) {
                    $issues[] = ['level' => 'high', 'key' => 'file_security_disabled', 'message' => 'File upload/download/document security should be enabled in production.'];
                }
                if (array_key_exists('deny_by_default', $fileSecurity) && empty($fileSecurity['deny_by_default'])) {
                    $issues[] = ['level' => 'high', 'key' => 'file_security_not_deny_by_default', 'message' => 'File security policies should deny by default in production.'];
                }
                if (array_key_exists('deny_download_until_scan_passed', $fileSecurity) && empty($fileSecurity['deny_download_until_scan_passed'])) {
                    $issues[] = ['level' => 'high', 'key' => 'file_download_before_scan_allowed', 'message' => 'Production downloads should be denied until upload scanning has passed.'];
                }
                if (empty($fileSecurity['policies']) || !is_array($fileSecurity['policies'])) {
                    $issues[] = ['level' => 'medium', 'key' => 'file_security_policies_missing', 'message' => 'Define file security policies for protected downloads, deletes, previews, and document access.'];
                }
                $download = is_array($fileSecurity['download'] ?? null) ? $fileSecurity['download'] : [];
                if (array_key_exists('nosniff', $download) && empty($download['nosniff'])) {
                    $issues[] = ['level' => 'medium', 'key' => 'download_nosniff_disabled', 'message' => 'Protected download responses should include X-Content-Type-Options: nosniff.'];
                }
                if (!empty($download['allow_inline'])) {
                    $issues[] = ['level' => 'medium', 'key' => 'inline_file_preview_enabled', 'message' => 'Inline previews should be limited to explicitly safe profiles and sandboxed preview pages.'];
                }
                $inspection = is_array($fileSecurity['inspection'] ?? null) ? $fileSecurity['inspection'] : [];
                if (array_key_exists('enabled', $inspection) && empty($inspection['enabled'])) {
                    $issues[] = ['level' => 'medium', 'key' => 'document_inspection_disabled', 'message' => 'Enable document/archive inspection hooks for production uploads.'];
                }
            }

            if (is_array($trustBoundaries)) {
                if (array_key_exists('enabled', $trustBoundaries) && empty($trustBoundaries['enabled'])) {
                    $issues[] = ['level' => 'high', 'key' => 'trust_boundaries_disabled', 'message' => 'Trust boundary enforcement should be enabled in production for protected resources.'];
                }
                if (empty($trustBoundaries['rules'])) {
                    $issues[] = ['level' => 'medium', 'key' => 'trust_boundary_rules_missing', 'message' => 'Define trust boundary rules for sensitive resources and internal system actions.'];
                }
                if (array_key_exists('deny_unclassified_fields', $trustBoundaries) && empty($trustBoundaries['deny_unclassified_fields'])) {
                    $issues[] = ['level' => 'medium', 'key' => 'trust_boundary_allows_unclassified_fields', 'message' => 'Production response filtering should deny or explicitly classify sensitive resource fields.'];
                }
            }
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
            if (array_key_exists('block_untrusted_forwarded_headers', $originProtection) && empty($originProtection['block_untrusted_forwarded_headers'])) {
                $issues[] = ['level' => 'medium', 'key' => 'untrusted_forwarded_headers_allowed', 'message' => 'Reject spoofed Forwarded/X-Forwarded-* headers from untrusted clients in production.'];
            }
            if (!empty($originProtection['cdn_or_proxy_enabled']) && empty($app['trusted_proxies'])) {
                $issues[] = ['level' => 'medium', 'key' => 'cdn_enabled_without_trusted_proxies', 'message' => 'CDN/proxy mode is enabled, but app.trusted_proxies is empty; forwarded client IP/host/proto headers will not be trusted.'];
            }
            if (!empty($originProtection['require_trusted_proxy']) && empty($app['trusted_proxies'])) {
                $issues[] = ['level' => 'high', 'key' => 'require_trusted_proxy_without_proxies', 'message' => 'require_trusted_proxy is enabled but no trusted proxy IP/CIDR ranges are configured.'];
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
            if (empty($uploads['strict_production'])) {
                $issues[] = ['level' => 'medium', 'key' => 'upload_strict_production_disabled', 'message' => 'Enable strict production upload mode to force randomized names, double-extension blocking, and executable-content rejection.'];
            }
            $archiveExtensions = ['zip', 'tar', 'gz', 'tgz', 'rar', '7z'];
            $selectedProfile = strtolower((string)($uploads['profile'] ?? 'custom'));
            $archiveUploadEnabled = $selectedProfile === 'archives' || (!empty($uploads['allowed_extensions']) && array_intersect((array)$uploads['allowed_extensions'], $archiveExtensions));
            if ($archiveUploadEnabled && empty($uploads['allow_archives_in_production'])) {
                $issues[] = ['level' => 'high', 'key' => 'archives_allowed_without_production_opt_in', 'message' => 'Archive uploads are high risk in production and should require explicit opt-in.'];
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
