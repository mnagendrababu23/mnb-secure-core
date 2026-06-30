<?php
namespace Mnb\SecurityCore\Http;

class SecurityHeadersBuilder
{
    private array $config;

    public function __construct(array $config = [])
    {
        $this->config = $config;
    }

    public function headers(?string $cspNonce = null, ?Request $request = null): array
    {
        if (array_key_exists('enabled', $this->config) && $this->config['enabled'] === false) {
            return [];
        }

        $headers = [];
        $headers['X-Content-Type-Options'] = $this->safeHeaderValue((string)($this->config['content_type_options'] ?? 'nosniff'), 'nosniff');
        $headers['Referrer-Policy'] = $this->safeHeaderValue((string)($this->config['referrer_policy'] ?? 'strict-origin-when-cross-origin'), 'strict-origin-when-cross-origin');

        $xFrameOptions = $this->config['x_frame_options'] ?? 'SAMEORIGIN';
        if ($xFrameOptions !== false && $xFrameOptions !== null && trim((string)$xFrameOptions) !== '') {
            $headers['X-Frame-Options'] = $this->safeHeaderValue(strtoupper((string)$xFrameOptions), 'SAMEORIGIN');
        }

        $permissionsPolicy = $this->permissionsPolicy();
        if ($permissionsPolicy !== null) {
            $headers['Permissions-Policy'] = $permissionsPolicy;
        }

        foreach ($this->crossOriginHeaders() as $name => $value) {
            $headers[$name] = $value;
        }

        $csp = $this->contentSecurityPolicy($cspNonce);
        if ($csp !== null) {
            $headerName = !empty($this->cspConfig()['report_only'])
                ? 'Content-Security-Policy-Report-Only'
                : 'Content-Security-Policy';
            $headers[$headerName] = $csp;
        }

        $hsts = $this->hsts($request);
        if ($hsts !== null) {
            $headers['Strict-Transport-Security'] = $hsts;
        }

        return $headers;
    }

    public function contentSecurityPolicy(?string $nonce = null): ?string
    {
        $csp = $this->cspConfig();
        if (array_key_exists('enabled', $csp) && $csp['enabled'] === false) {
            return null;
        }

        $directives = $this->directives($csp);
        if ($nonce !== null && $nonce !== '' && !empty($csp['nonce_enabled'])) {
            $safeNonce = $this->safeNonce($nonce);
            if ($safeNonce === '') {
                $nonce = null;
            }
        }

        if ($nonce !== null && $nonce !== '' && !empty($csp['nonce_enabled'])) {
            $safeNonce = $this->safeNonce($nonce);
            $nonceDirectives = $csp['nonce_directives'] ?? ['script-src', 'style-src'];
            if (!is_array($nonceDirectives)) {
                $nonceDirectives = ['script-src'];
            }
            foreach ($nonceDirectives as $directive) {
                $directive = $this->safeDirectiveName((string)$directive);
                if ($directive === null) {
                    continue;
                }
                $directives[$directive] ??= ["'self'"];
                $directives[$directive][] = "'nonce-" . $safeNonce . "'";
            }
        }

        $parts = [];
        foreach ($directives as $name => $sources) {
            $safeName = $this->safeDirectiveName((string)$name);
            if ($safeName === null) {
                continue;
            }
            $safeSources = $this->safeSources($sources);
            if ($safeSources === []) {
                $parts[] = $safeName;
                continue;
            }
            $parts[] = $safeName . ' ' . implode(' ', array_values(array_unique($safeSources)));
        }

        return $parts === [] ? null : implode('; ', $parts) . ';';
    }

    public function hsts(?Request $request = null): ?string
    {
        $hsts = $this->config['hsts'] ?? false;
        if ($hsts === false || $hsts === null || $hsts === '' || $hsts === []) {
            return null;
        }

        $settings = is_array($hsts) ? $hsts : ['enabled' => (bool)$hsts];
        if (array_key_exists('enabled', $settings) && !$settings['enabled']) {
            return null;
        }

        $onlyOnHttps = array_key_exists('only_on_https', $settings) ? (bool)$settings['only_on_https'] : true;
        if ($request !== null && $onlyOnHttps && !$request->isSecure()) {
            return null;
        }

        $maxAge = (int)($settings['max_age'] ?? 31536000);
        if ($maxAge < 0) {
            $maxAge = 0;
        }

        $value = 'max-age=' . $maxAge;
        if (array_key_exists('include_subdomains', $settings) ? (bool)$settings['include_subdomains'] : true) {
            $value .= '; includeSubDomains';
        }
        if (!empty($settings['preload'])) {
            $value .= '; preload';
        }

        return $value;
    }

    public function permissionsPolicy(): ?string
    {
        $config = $this->config['permissions_policy'] ?? ['preset' => 'strict'];
        if ($config === false || $config === null) {
            return null;
        }
        if (is_string($config)) {
            $config = ['preset' => $config];
        }
        if (!is_array($config)) {
            $config = ['preset' => 'strict'];
        }

        $preset = strtolower((string)($config['preset'] ?? 'strict'));
        if ($preset === 'none' || $preset === 'disabled' || $preset === 'off') {
            return null;
        }

        $directives = match ($preset) {
            'balanced' => [
                'camera' => [],
                'microphone' => [],
                'geolocation' => [],
                'payment' => [],
                'usb' => [],
                'fullscreen' => ['self'],
                'picture-in-picture' => ['self'],
            ],
            'minimal' => [
                'camera' => [],
                'microphone' => [],
                'geolocation' => [],
            ],
            'custom' => [],
            default => [
                'accelerometer' => [],
                'ambient-light-sensor' => [],
                'autoplay' => [],
                'battery' => [],
                'camera' => [],
                'display-capture' => [],
                'document-domain' => [],
                'encrypted-media' => [],
                'fullscreen' => ['self'],
                'geolocation' => [],
                'gyroscope' => [],
                'magnetometer' => [],
                'microphone' => [],
                'midi' => [],
                'payment' => [],
                'picture-in-picture' => [],
                'publickey-credentials-get' => ['self'],
                'screen-wake-lock' => [],
                'sync-xhr' => [],
                'usb' => [],
                'web-share' => [],
                'xr-spatial-tracking' => [],
            ],
        };

        foreach ((array)($config['directives'] ?? []) as $name => $allowList) {
            $safeName = $this->safeDirectiveName((string)$name);
            if ($safeName === null) {
                continue;
            }
            $directives[$safeName] = is_array($allowList) ? $allowList : [$allowList];
        }

        $parts = [];
        foreach ($directives as $feature => $allowList) {
            $safeFeature = $this->safeDirectiveName((string)$feature);
            if ($safeFeature === null) {
                continue;
            }
            $allow = $this->permissionsAllowList($allowList);
            $parts[] = $safeFeature . '=' . $allow;
        }

        return $parts === [] ? null : implode(', ', $parts);
    }

    public static function wantsAutoNonce(array $config): bool
    {
        $csp = $config['csp'] ?? [];
        return is_array($csp) && !empty($csp['auto_nonce']);
    }

    private function cspConfig(): array
    {
        $csp = $this->config['csp'] ?? [];
        if (!is_array($csp)) {
            $csp = ['enabled' => (bool)$csp];
        }
        $csp += [
            'enabled' => true,
            'report_only' => false,
            'nonce_enabled' => true,
            'nonce_directives' => ['script-src', 'style-src'],
        ];
        return $csp;
    }

    private function directives(array $csp): array
    {
        $directives = $csp['directives'] ?? null;
        if (is_array($directives) && $directives !== []) {
            return $directives;
        }

        $frameAncestors = $this->config['frame_ancestors'] ?? "'self'";
        return [
            'default-src' => ["'self'"],
            'script-src' => ["'self'"],
            'style-src' => ["'self'"],
            'img-src' => ["'self'", 'data:'],
            'font-src' => ["'self'", 'data:'],
            'connect-src' => ["'self'"],
            'object-src' => ["'none'"],
            'base-uri' => ["'self'"],
            'form-action' => ["'self'"],
            'frame-ancestors' => is_array($frameAncestors) ? $frameAncestors : [(string)$frameAncestors],
        ];
    }

    private function crossOriginHeaders(): array
    {
        $headers = [];
        foreach ([
            'cross_origin_opener_policy' => 'Cross-Origin-Opener-Policy',
            'cross_origin_resource_policy' => 'Cross-Origin-Resource-Policy',
            'cross_origin_embedder_policy' => 'Cross-Origin-Embedder-Policy',
        ] as $configKey => $headerName) {
            $value = $this->config[$configKey] ?? null;
            if ($value === null || $value === false || trim((string)$value) === '') {
                continue;
            }
            $headers[$headerName] = $this->safeHeaderValue((string)$value, 'same-origin');
        }
        return $headers;
    }

    private function safeSources(mixed $sources): array
    {
        if (is_string($sources)) {
            $sources = preg_split('/\s+/', trim($sources)) ?: [];
        }
        if (!is_array($sources)) {
            return [];
        }
        $safe = [];
        foreach ($sources as $source) {
            if (!is_scalar($source)) {
                continue;
            }
            $source = trim((string)$source);
            if ($source === '' || str_contains($source, ';') || preg_match('/[\r\n]/', $source)) {
                continue;
            }
            $safe[] = $source;
        }
        return $safe;
    }

    private function permissionsAllowList(mixed $allowList): string
    {
        if ($allowList === [] || $allowList === null || $allowList === false) {
            return '()';
        }
        if ($allowList === true) {
            return '(*)';
        }
        if (is_string($allowList)) {
            $allowList = [$allowList];
        }
        if (!is_array($allowList)) {
            return '()';
        }
        $tokens = [];
        foreach ($allowList as $token) {
            if (!is_scalar($token)) {
                continue;
            }
            $token = trim((string)$token);
            if ($token === '' || str_contains($token, ';') || preg_match('/[\r\n,()]/', $token)) {
                continue;
            }
            $tokens[] = $token === 'self' ? 'self' : $token;
        }
        return $tokens === [] ? '()' : '(' . implode(' ', array_values(array_unique($tokens))) . ')';
    }

    private function safeDirectiveName(string $name): ?string
    {
        $name = strtolower(trim($name));
        if ($name === '' || !preg_match('/^[a-z][a-z0-9-]*$/', $name)) {
            return null;
        }
        return $name;
    }

    private function safeHeaderValue(string $value, string $fallback): string
    {
        $value = trim($value);
        if ($value === '' || preg_match('/[\r\n]/', $value)) {
            return $fallback;
        }
        return $value;
    }

    private function safeNonce(string $nonce): string
    {
        $nonce = trim($nonce);
        return preg_match('/^[A-Za-z0-9+\/_=-]+$/', $nonce) ? $nonce : '';
    }
}
