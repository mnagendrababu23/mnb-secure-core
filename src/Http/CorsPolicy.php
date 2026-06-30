<?php
namespace Mnb\SecurityCore\Http;

class CorsPolicy
{
    /** @var list<string> */
    private array $allowedOrigins;
    /** @var list<string> */
    private array $allowedOriginPatterns;
    /** @var list<string> */
    private array $allowedMethods;
    /** @var list<string> */
    private array $allowedHeaders;
    /** @var list<string> */
    private array $exposedHeaders;

    public function __construct(private array $config = [])
    {
        $this->allowedOrigins = $this->normalizeList($config['allowed_origins'] ?? []);
        $this->allowedOriginPatterns = $this->normalizeList($config['allowed_origin_patterns'] ?? []);
        $this->allowedMethods = array_map('strtoupper', $this->normalizeList($config['allowed_methods'] ?? ['GET', 'POST', 'OPTIONS']));
        $this->allowedHeaders = array_map('strtolower', $this->normalizeList($config['allowed_headers'] ?? ['Content-Type', 'Authorization']));
        $this->exposedHeaders = $this->normalizeList($config['exposed_headers'] ?? []);
    }

    public function enabled(): bool
    {
        return !array_key_exists('enabled', $this->config) || $this->config['enabled'] !== false;
    }

    public function allowCredentials(): bool
    {
        return !empty($this->config['allow_credentials']);
    }

    public function allowNullOrigin(): bool
    {
        return !empty($this->config['allow_null_origin']);
    }

    public function allowPrivateNetwork(): bool
    {
        return !empty($this->config['allow_private_network']);
    }

    public function maxAge(): int
    {
        return max(0, (int)($this->config['max_age'] ?? 600));
    }

    public function originAllowed(?string $origin): bool
    {
        if ($origin === null || trim($origin) === '') {
            return true;
        }

        $origin = $this->normalizeOrigin($origin);
        if ($origin === null) {
            return false;
        }

        if ($origin === 'null') {
            return $this->allowNullOrigin();
        }

        if (in_array('*', $this->allowedOrigins, true)) {
            return !$this->allowCredentials();
        }

        if (in_array($origin, $this->allowedOrigins, true)) {
            return true;
        }

        foreach ($this->allowedOriginPatterns as $pattern) {
            if ($this->matchesOriginPattern($origin, $pattern)) {
                return true;
            }
        }

        return false;
    }

    public function responseOrigin(?string $origin): ?string
    {
        if ($origin === null || trim($origin) === '') {
            return null;
        }
        $origin = $this->normalizeOrigin($origin);
        if ($origin === null || !$this->originAllowed($origin)) {
            return null;
        }
        if (in_array('*', $this->allowedOrigins, true) && !$this->allowCredentials()) {
            return '*';
        }
        return $origin;
    }

    public function methodAllowed(?string $method): bool
    {
        if ($method === null || trim($method) === '') {
            return true;
        }
        return in_array(strtoupper(trim($method)), $this->allowedMethods, true);
    }

    public function requestedHeadersAllowed(?string $requestedHeaders): bool
    {
        if ($requestedHeaders === null || trim($requestedHeaders) === '') {
            return true;
        }
        if (in_array('*', $this->allowedHeaders, true)) {
            return true;
        }
        foreach (explode(',', $requestedHeaders) as $header) {
            $header = strtolower(trim($header));
            if ($header === '') {
                continue;
            }
            if (!in_array($header, $this->allowedHeaders, true)) {
                return false;
            }
        }
        return true;
    }

    public function apply(Request $request, Response $response, ?string $origin): Response
    {
        $allowOrigin = $this->responseOrigin($origin);
        if ($allowOrigin === null) {
            return $response;
        }

        $response = $response
            ->withHeader('Access-Control-Allow-Origin', $allowOrigin)
            ->withHeader('Vary', $this->varyHeader($response));

        if ($this->allowCredentials()) {
            $response = $response->withHeader('Access-Control-Allow-Credentials', 'true');
        }

        if ($this->exposedHeaders !== []) {
            $response = $response->withHeader('Access-Control-Expose-Headers', implode(', ', $this->exposedHeaders));
        }

        if ($request->method() === 'OPTIONS') {
            $response = $response
                ->withHeader('Access-Control-Allow-Methods', implode(', ', $this->allowedMethods))
                ->withHeader('Access-Control-Allow-Headers', implode(', ', array_map($this->canonicalHeader(...), $this->allowedHeaders)))
                ->withHeader('Access-Control-Max-Age', (string)$this->maxAge());

            if ($this->allowPrivateNetwork() && strtolower((string)$request->header('access-control-request-private-network')) === 'true') {
                $response = $response->withHeader('Access-Control-Allow-Private-Network', 'true');
            }
        }

        return $response;
    }

    /** @return list<string> */
    private function normalizeList(mixed $value): array
    {
        if (is_string($value)) {
            $value = explode(',', $value);
        }
        if (!is_array($value)) {
            return [];
        }
        $items = [];
        foreach ($value as $item) {
            if (!is_scalar($item)) {
                continue;
            }
            $item = trim((string)$item);
            if ($item !== '') {
                $items[] = $item;
            }
        }
        return array_values(array_unique($items));
    }

    private function normalizeOrigin(string $origin): ?string
    {
        $origin = trim($origin);
        if ($origin === 'null') {
            return 'null';
        }
        if (preg_match('/[\r\n]/', $origin)) {
            return null;
        }
        $parts = parse_url($origin);
        if (!is_array($parts) || empty($parts['scheme']) || empty($parts['host'])) {
            return null;
        }
        $scheme = strtolower((string)$parts['scheme']);
        if (!in_array($scheme, ['http', 'https'], true)) {
            return null;
        }
        $host = strtolower((string)$parts['host']);
        $port = isset($parts['port']) ? ':' . (int)$parts['port'] : '';
        return $scheme . '://' . $host . $port;
    }

    private function matchesOriginPattern(string $origin, string $pattern): bool
    {
        $pattern = trim($pattern);
        if ($pattern === '') {
            return false;
        }
        if (preg_match('/[\r\n]/', $pattern)) {
            return false;
        }
        $quoted = preg_quote($pattern, '/');
        $quoted = str_replace('\\*', '[A-Za-z0-9.-]+', $quoted);
        return (bool)preg_match('/^' . $quoted . '$/i', $origin);
    }

    private function canonicalHeader(string $header): string
    {
        if ($header === '*') {
            return '*';
        }
        return implode('-', array_map(fn(string $part): string => ucfirst($part), explode('-', strtolower($header))));
    }

    private function varyHeader(Response $response): string
    {
        $existing = $response->headers()['Vary'] ?? '';
        $parts = array_filter(array_map('trim', explode(',', (string)$existing)));
        foreach (['Origin', 'Access-Control-Request-Method', 'Access-Control-Request-Headers'] as $part) {
            if (!in_array($part, $parts, true)) {
                $parts[] = $part;
            }
        }
        return implode(', ', $parts);
    }
}
