<?php
namespace Mnb\SecurityCore\Http;

class RequestTrust
{
    public const FORWARDED_HEADERS = [
        'forwarded',
        'x-forwarded-for',
        'x-forwarded-proto',
        'x-forwarded-host',
        'x-forwarded-port',
        'x-real-ip',
        'cf-connecting-ip',
        'true-client-ip',
        'fastly-client-ip',
    ];

    /** @param array<string,mixed> $server */
    public static function remoteIp(array $server): string
    {
        $remote = trim((string)($server['REMOTE_ADDR'] ?? ''));
        return self::normalizeIp($remote) ?: '0.0.0.0';
    }

    /** @param array<string,mixed> $headers @param array<string,mixed> $server @param array<int,string> $trustedProxies */
    public static function clientIp(array $headers, array $server, array $trustedProxies = []): string
    {
        $remoteIp = self::remoteIp($server);
        if (!self::isTrustedProxy($remoteIp, $trustedProxies)) {
            return $remoteIp;
        }

        $chain = self::forwardedForChain($headers, $server);
        if ($chain !== []) {
            $chain[] = $remoteIp;
            for ($i = count($chain) - 1; $i >= 0; $i--) {
                $candidate = self::normalizeIp((string)$chain[$i]);
                if ($candidate === null) {
                    continue;
                }
                if (!self::isTrustedProxy($candidate, $trustedProxies)) {
                    return $candidate;
                }
            }
        }

        foreach (['cf-connecting-ip', 'true-client-ip', 'fastly-client-ip', 'x-real-ip'] as $headerName) {
            $candidate = self::normalizeIp((string)self::header($headers, $server, $headerName, ''));
            if ($candidate !== null) {
                return $candidate;
            }
        }

        return $remoteIp;
    }

    /** @param array<string,mixed> $headers @param array<string,mixed> $server @param array<int,string> $trustedProxies */
    public static function isSecure(array $headers, array $server, array $trustedProxies = []): bool
    {
        $https = strtolower((string)($server['HTTPS'] ?? ''));
        if ($https !== '' && $https !== 'off' && $https !== '0') {
            return true;
        }

        if (!self::isTrustedProxy(self::remoteIp($server), $trustedProxies)) {
            return false;
        }

        $proto = self::forwardedProto($headers, $server);
        if ($proto !== null) {
            return $proto === 'https';
        }

        $forwardedSsl = strtolower(trim((string)self::header($headers, $server, 'x-forwarded-ssl', '')));
        if ($forwardedSsl === 'on') {
            return true;
        }

        $frontEndHttps = strtolower(trim((string)self::header($headers, $server, 'front-end-https', '')));
        return $frontEndHttps === 'on';
    }

    /** @param array<string,mixed> $headers @param array<string,mixed> $server */
    public static function forwardedProto(array $headers, array $server): ?string
    {
        $forwarded = self::forwardedHeaderParams($headers, $server);
        if (isset($forwarded['proto'])) {
            $proto = strtolower(trim((string)$forwarded['proto']));
            if (in_array($proto, ['http', 'https'], true)) {
                return $proto;
            }
        }

        $value = self::firstListValue((string)self::header($headers, $server, 'x-forwarded-proto', ''));
        $value = strtolower(trim($value));
        return in_array($value, ['http', 'https'], true) ? $value : null;
    }

    /** @param array<string,mixed> $headers @param array<string,mixed> $server @param array<int,string> $trustedProxies */
    public static function forwardedHost(array $headers, array $server, array $trustedProxies = []): ?string
    {
        if (!self::isTrustedProxy(self::remoteIp($server), $trustedProxies)) {
            return null;
        }

        $forwarded = self::forwardedHeaderParams($headers, $server);
        if (isset($forwarded['host'])) {
            $host = self::normalizeHost((string)$forwarded['host']);
            if (self::isSafeHost($host)) {
                return $host;
            }
        }

        $host = self::normalizeHost(self::firstListValue((string)self::header($headers, $server, 'x-forwarded-host', '')));
        return self::isSafeHost($host) ? $host : null;
    }

    /** @param array<string,mixed> $headers @param array<string,mixed> $server @param array<int,string> $trustedProxies */
    public static function forwardedPort(array $headers, array $server, array $trustedProxies = []): ?int
    {
        if (!self::isTrustedProxy(self::remoteIp($server), $trustedProxies)) {
            return null;
        }

        $value = self::firstListValue((string)self::header($headers, $server, 'x-forwarded-port', ''));
        if ($value === '' || !ctype_digit($value)) {
            return null;
        }
        $port = (int)$value;
        return $port >= 1 && $port <= 65535 ? $port : null;
    }

    /** @param array<string,mixed> $headers @param array<string,mixed> $server */
    public static function host(array $headers, array $server): string
    {
        $host = (string)($server['HTTP_HOST'] ?? self::header($headers, $server, 'host', ''));
        return self::normalizeHost($host);
    }

    /** @param array<string,mixed> $headers @param array<string,mixed> $server @param array<int,string> $trustedProxies */
    public static function effectiveHost(array $headers, array $server, array $trustedProxies = []): string
    {
        return self::forwardedHost($headers, $server, $trustedProxies) ?: self::host($headers, $server);
    }

    /** @param array<string,mixed> $headers @param array<string,mixed> $server */
    public static function hasForwardedHeaders(array $headers, array $server): bool
    {
        foreach (self::FORWARDED_HEADERS as $header) {
            if (self::header($headers, $server, $header, '') !== '') {
                return true;
            }
        }
        return false;
    }

    /** @param array<int,string> $trustedProxies */
    public static function isTrustedProxy(string $ip, array $trustedProxies): bool
    {
        $ip = self::normalizeIp($ip) ?: '';
        if ($ip === '') {
            return false;
        }

        foreach (self::normalizeTrustedProxies($trustedProxies) as $proxy) {
            if ($proxy === '*') {
                return true;
            }
            if (self::ipMatches($ip, $proxy)) {
                return true;
            }
        }
        return false;
    }

    /** @param array<int,string> $trustedProxies @return array<int,string> */
    public static function normalizeTrustedProxies(array $trustedProxies): array
    {
        $normalized = [];
        foreach ($trustedProxies as $proxy) {
            $proxy = trim((string)$proxy);
            if ($proxy !== '') {
                $normalized[] = $proxy;
            }
        }
        return array_values(array_unique($normalized));
    }

    public static function normalizeHost(string $host): string
    {
        $host = trim(strtolower($host));
        $host = trim($host, " \t\n\r\0\x0B\"'");

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

    public static function isSafeHost(string $host): bool
    {
        if ($host === '' || strlen($host) > 253) {
            return false;
        }
        if (preg_match('/[\x00-\x20\x7f]/', $host)) {
            return false;
        }
        if (str_contains($host, '@') || str_contains($host, '/') || str_contains($host, '\\')) {
            return false;
        }
        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            return true;
        }
        return (bool)preg_match('/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i', $host);
    }

    public static function normalizeIp(string $value): ?string
    {
        $value = trim($value);
        $value = trim($value, " \t\n\r\0\x0B\"'");
        if ($value === '' || strtolower($value) === 'unknown') {
            return null;
        }

        if (str_starts_with($value, '[')) {
            $end = strpos($value, ']');
            $value = $end === false ? trim($value, '[]') : substr($value, 1, $end - 1);
        } elseif (substr_count($value, ':') === 1 && str_contains($value, '.')) {
            [$value] = explode(':', $value, 2);
        }

        return filter_var($value, FILTER_VALIDATE_IP) !== false ? $value : null;
    }

    /** @param array<string,mixed> $headers @param array<string,mixed> $server @return array<int,string> */
    private static function forwardedForChain(array $headers, array $server): array
    {
        $chain = [];

        $forwarded = (string)self::header($headers, $server, 'forwarded', '');
        foreach (self::splitList($forwarded) as $entry) {
            $params = self::parseForwardedEntry($entry);
            if (isset($params['for'])) {
                $ip = self::normalizeIp((string)$params['for']);
                if ($ip !== null) {
                    $chain[] = $ip;
                }
            }
        }

        $xff = (string)self::header($headers, $server, 'x-forwarded-for', '');
        foreach (self::splitList($xff) as $entry) {
            $ip = self::normalizeIp($entry);
            if ($ip !== null) {
                $chain[] = $ip;
            }
        }

        return array_values(array_unique($chain));
    }

    /** @param array<string,mixed> $headers @param array<string,mixed> $server @return array<string,string> */
    private static function forwardedHeaderParams(array $headers, array $server): array
    {
        $forwarded = self::firstListValue((string)self::header($headers, $server, 'forwarded', ''));
        return $forwarded === '' ? [] : self::parseForwardedEntry($forwarded);
    }

    /** @return array<string,string> */
    private static function parseForwardedEntry(string $entry): array
    {
        $params = [];
        foreach (explode(';', $entry) as $part) {
            if (!str_contains($part, '=')) {
                continue;
            }
            [$key, $value] = explode('=', $part, 2);
            $key = strtolower(trim($key));
            $value = trim($value, " \t\n\r\0\x0B\"'");
            if ($key !== '') {
                $params[$key] = $value;
            }
        }
        return $params;
    }

    /** @return array<int,string> */
    private static function splitList(string $value): array
    {
        if (trim($value) === '') {
            return [];
        }
        return array_values(array_filter(array_map('trim', explode(',', $value)), fn(string $part): bool => $part !== ''));
    }

    private static function firstListValue(string $value): string
    {
        return self::splitList($value)[0] ?? '';
    }

    /** @param array<string,mixed> $headers @param array<string,mixed> $server */
    private static function header(array $headers, array $server, string $name, mixed $default = null): mixed
    {
        $normalizedHeaders = array_change_key_case($headers, CASE_LOWER);
        $lower = strtolower($name);
        if (array_key_exists($lower, $normalizedHeaders)) {
            return $normalizedHeaders[$lower];
        }

        $serverKey = 'HTTP_' . strtoupper(str_replace('-', '_', $name));
        if (array_key_exists($serverKey, $server)) {
            return $server[$serverKey];
        }

        if ($lower === 'content-type' && array_key_exists('CONTENT_TYPE', $server)) {
            return $server['CONTENT_TYPE'];
        }
        if ($lower === 'content-length' && array_key_exists('CONTENT_LENGTH', $server)) {
            return $server['CONTENT_LENGTH'];
        }

        return $default;
    }

    private static function ipMatches(string $ip, string $trustedProxy): bool
    {
        if ($trustedProxy === '*') {
            return true;
        }
        if ($ip === $trustedProxy) {
            return true;
        }
        if (!str_contains($trustedProxy, '/')) {
            return false;
        }

        [$subnet, $bits] = explode('/', $trustedProxy, 2);
        if (!ctype_digit($bits)) {
            return false;
        }

        $bits = (int)$bits;
        $ipBinary = @inet_pton($ip);
        $subnetBinary = @inet_pton($subnet);
        if ($ipBinary === false || $subnetBinary === false || strlen($ipBinary) !== strlen($subnetBinary)) {
            return false;
        }

        $maxBits = strlen($ipBinary) * 8;
        if ($bits < 0 || $bits > $maxBits) {
            return false;
        }

        $bytes = intdiv($bits, 8);
        $remainingBits = $bits % 8;
        if ($bytes > 0 && substr($ipBinary, 0, $bytes) !== substr($subnetBinary, 0, $bytes)) {
            return false;
        }
        if ($remainingBits === 0) {
            return true;
        }
        $mask = (0xFF << (8 - $remainingBits)) & 0xFF;
        return (ord($ipBinary[$bytes]) & $mask) === (ord($subnetBinary[$bytes]) & $mask);
    }
}
