<?php
namespace Mnb\SecurityCore\Http;

class Request
{
    /** @var array<string,mixed> */
    private array $attributes = [];

    public function __construct(
        private string $method,
        private string $path,
        private array $query = [],
        private array $body = [],
        private array $headers = [],
        private array $server = [],
        private array $trustedProxies = []
    ) {
        $this->headers = array_change_key_case($headers, CASE_LOWER);
        $this->trustedProxies = RequestTrust::normalizeTrustedProxies($trustedProxies);
    }

    public static function fromGlobals(array $trustedProxies = []): self
    {
        $headers = function_exists('getallheaders') ? getallheaders() : [];
        $uri = $_SERVER['REQUEST_URI'] ?? '/';
        $path = parse_url($uri, PHP_URL_PATH) ?: '/';
        $body = $_POST;
        $rawBody = file_get_contents('php://input') ?: '';
        $contentType = strtolower($headers['Content-Type'] ?? $headers['content-type'] ?? '');
        if (str_contains($contentType, 'application/json')) {
            $json = json_decode($rawBody !== '' ? $rawBody : '[]', true);
            if (is_array($json)) {
                $body = $json;
            }
        }
        return (new self($_SERVER['REQUEST_METHOD'] ?? 'GET', $path, $_GET, $body, $headers, $_SERVER, $trustedProxies))
            ->withAttribute('raw_body', $rawBody);
    }

    public function method(): string { return strtoupper($this->method); }
    public function path(): string { return $this->path; }
    public function query(string $key, mixed $default = null): mixed { return $this->query[$key] ?? $default; }
    public function input(string $key, mixed $default = null): mixed { return $this->body[$key] ?? $default; }
    /** @return array<string,mixed> */
    public function queryParams(): array { return $this->query; }
    /** @return array<string,mixed> */
    public function body(): array { return $this->body; }
    public function validated(string $key, mixed $default = null): mixed
    {
        $validated = $this->attribute('validated_input', []);
        if (!is_array($validated)) {
            return $default;
        }
        foreach (['body', 'query', 'all'] as $location) {
            if (isset($validated[$location]) && is_array($validated[$location]) && array_key_exists($key, $validated[$location])) {
                return $validated[$location][$key];
            }
        }
        return $default;
    }
    public function all(): array { return array_merge($this->query, $this->body); }
    public function header(string $name, mixed $default = null): mixed { return $this->headers[strtolower($name)] ?? $default; }

    public function bearerToken(): ?string
    {
        $authorization = $this->header('authorization');
        if (!$authorization && isset($this->server['HTTP_AUTHORIZATION'])) {
            $authorization = $this->server['HTTP_AUTHORIZATION'];
        }
        if (!$authorization || stripos($authorization, 'Bearer ') !== 0) {
            return null;
        }
        return trim(substr($authorization, 7));
    }

    /**
     * Returns the best client IP for application-level decisions. Forwarded IPs are
     * accepted only when the immediate REMOTE_ADDR matches a configured trusted proxy.
     */
    public function ip(): string { return $this->clientIp(); }

    public function clientIp(): string
    {
        return RequestTrust::clientIp($this->headers, $this->server, $this->trustedProxies);
    }

    /** Returns the immediate peer IP that connected to PHP/web server. */
    public function remoteIp(): string
    {
        return RequestTrust::remoteIp($this->server);
    }

    /** Returns the raw Host header normalized, without trusting forwarded headers. */
    public function host(): string
    {
        return RequestTrust::host($this->headers, $this->server);
    }

    /** Returns trusted X-Forwarded-Host/Forwarded host when available, otherwise Host. */
    public function effectiveHost(): string
    {
        return RequestTrust::effectiveHost($this->headers, $this->server, $this->trustedProxies);
    }

    public function trustedForwardedHost(): ?string
    {
        return RequestTrust::forwardedHost($this->headers, $this->server, $this->trustedProxies);
    }

    public function trustedForwardedProto(): ?string
    {
        if (!$this->isFromTrustedProxy()) {
            return null;
        }
        return RequestTrust::forwardedProto($this->headers, $this->server);
    }

    public function trustedForwardedPort(): ?int
    {
        return RequestTrust::forwardedPort($this->headers, $this->server, $this->trustedProxies);
    }

    public function hasForwardedHeaders(): bool
    {
        return RequestTrust::hasForwardedHeaders($this->headers, $this->server);
    }

    public function isSecure(): bool
    {
        return RequestTrust::isSecure($this->headers, $this->server, $this->trustedProxies);
    }

    public function withTrustedProxies(array $trustedProxies): self
    {
        $clone = clone $this;
        $clone->trustedProxies = RequestTrust::normalizeTrustedProxies($trustedProxies);
        return $clone;
    }

    public function isFromTrustedProxy(): bool
    {
        return RequestTrust::isTrustedProxy($this->remoteIp(), $this->trustedProxies);
    }


    /** @param array<string,mixed> $query */
    public function withQuery(array $query): self
    {
        $clone = clone $this;
        $clone->query = $query;
        return $clone;
    }

    /** @param array<string,mixed> $body */
    public function withBody(array $body): self
    {
        $clone = clone $this;
        $clone->body = $body;
        return $clone;
    }

    public function attribute(string $key, mixed $default = null): mixed
    {
        return $this->attributes[$key] ?? $default;
    }

    public function withAttribute(string $key, mixed $value): self
    {
        $clone = clone $this;
        $clone->attributes[$key] = $value;
        return $clone;
    }

    public function contentLength(): int { return (int)($this->server['CONTENT_LENGTH'] ?? 0); }
}
