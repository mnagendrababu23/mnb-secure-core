<?php
namespace Mnb\SecurityCore\Security;

use Mnb\SecurityCore\Http\Request;
use Mnb\SecurityCore\Http\Response;
use Mnb\SecurityCore\Origin\ResponseFingerprintAnalyzer;

class ServerIdentityHider
{
    public const DEFAULT_STRIP_HEADERS = [
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
    ];

    public function __construct(private array $config = []) {}

    public function sanitizeResponse(Response $response): Response
    {
        $stripHeaders = $this->config['strip_headers'] ?? self::DEFAULT_STRIP_HEADERS;

        foreach ($stripHeaders as $headerName) {
            $response = $response->withoutHeader((string)$headerName);
        }

        if (!empty($this->config['hide_php_session_cookie_name'])) {
            $response = $response->withoutHeader('X-PHP-Origin');
        }

        return $response;
    }

    public function fingerprintReport(Response $response): array
    {
        return ResponseFingerprintAnalyzer::fromConfig(['origin_protection' => $this->config])->analyze($response->headers())->toArray();
    }

    public function shouldBlockDirectIpHost(Request $request): bool
    {
        if (empty($this->config['block_direct_ip_host'])) {
            return false;
        }

        return self::isIpAddressHost($request->effectiveHost());
    }

    public static function normalizeHost(string $host): string
    {
        $host = trim(strtolower($host));

        if ($host === '') {
            return '';
        }

        if (str_contains($host, '://')) {
            $parts = parse_url($host);
            $host = is_array($parts) ? (string)($parts['host'] ?? '') : '';
        }

        if (str_starts_with($host, '[')) {
            $end = strpos($host, ']');
            return $end === false ? trim($host, '[]') : substr($host, 1, $end - 1);
        }

        if (substr_count($host, ':') === 1) {
            [$host] = explode(':', $host, 2);
        }

        return trim($host, '.');
    }

    public static function isIpAddressHost(string $host): bool
    {
        $normalized = self::normalizeHost($host);
        return filter_var($normalized, FILTER_VALIDATE_IP) !== false;
    }

    public static function isPrivateOrReservedIp(string $ip): bool
    {
        $normalized = self::normalizeHost($ip);

        if (filter_var($normalized, FILTER_VALIDATE_IP) === false) {
            return false;
        }

        return filter_var(
            $normalized,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        ) === false;
    }

    /**
     * PHP can remove application-added fingerprint headers, but a web server or CDN must
     * also be configured to hide/replace low-level Server headers and to block direct
     * origin access. This helper returns deployment reminders for production reviews.
     */
    public static function deploymentChecklist(): array
    {
        return [
            'Put the public site behind a trusted CDN, reverse proxy, or load balancer.',
            'Proxy DNS records should hide the origin server where your DNS provider supports it.',
            'Firewall the origin server so only trusted proxy/CDN IP ranges can reach HTTP/HTTPS ports.',
            'Disable PHP expose_php and remove X-Powered-By headers.',
            'Remove or minimize Server/version headers at Nginx/Apache/CDN level.',
            'Block direct IP Host requests in the application and at web-server level.',
            'Keep APP_DEBUG=false and return safe public errors in production.',
        ];
    }
}
