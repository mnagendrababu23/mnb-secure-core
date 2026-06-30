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
        $this->trustedProxies = array_values(array_filter(array_map('trim', $trustedProxies), fn($proxy) => $proxy !== ''));
    }

    public static function fromGlobals(array $trustedProxies = []): self
    {
        $headers = function_exists('getallheaders') ? getallheaders() : [];
        $uri = $_SERVER['REQUEST_URI'] ?? '/';
        $path = parse_url($uri, PHP_URL_PATH) ?: '/';
        $body = $_POST;
        $contentType = strtolower($headers['Content-Type'] ?? $headers['content-type'] ?? '');
        if (str_contains($contentType, 'application/json')) {
            $json = json_decode(file_get_contents('php://input') ?: '[]', true);
            if (is_array($json)) {
                $body = $json;
            }
        }
        return new self($_SERVER['REQUEST_METHOD'] ?? 'GET', $path, $_GET, $body, $headers, $_SERVER, $trustedProxies);
    }

    public function method(): string { return strtoupper($this->method); }
    public function path(): string { return $this->path; }
    public function query(string $key, mixed $default = null): mixed { return $this->query[$key] ?? $default; }
    public function input(string $key, mixed $default = null): mixed { return $this->body[$key] ?? $default; }
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

    public function ip(): string { return $this->server['REMOTE_ADDR'] ?? '0.0.0.0'; }
    public function host(): string { return strtolower($this->server['HTTP_HOST'] ?? $this->header('host', '')); }

    public function isSecure(): bool
    {
        if (!empty($this->server['HTTPS']) && $this->server['HTTPS'] !== 'off') {
            return true;
        }

        $forwardedProto = strtolower((string)($this->server['HTTP_X_FORWARDED_PROTO'] ?? $this->header('x-forwarded-proto', '')));
        if ($forwardedProto === '') {
            return false;
        }

        $firstProto = trim(explode(',', $forwardedProto)[0]);
        return $firstProto === 'https' && $this->isFromTrustedProxy();
    }

    public function withTrustedProxies(array $trustedProxies): self
    {
        $clone = clone $this;
        $clone->trustedProxies = array_values(array_filter(array_map('trim', $trustedProxies), fn($proxy) => $proxy !== ''));
        return $clone;
    }

    public function isFromTrustedProxy(): bool
    {
        $remoteAddr = (string)($this->server['REMOTE_ADDR'] ?? '');
        if ($remoteAddr === '') {
            return false;
        }
        foreach ($this->trustedProxies as $proxy) {
            if ($this->ipMatches($remoteAddr, (string)$proxy)) {
                return true;
            }
        }
        return false;
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

    private function ipMatches(string $ip, string $trustedProxy): bool
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
        $bits = (int)$bits;
        $ipBinary = @inet_pton($ip);
        $subnetBinary = @inet_pton($subnet);
        if ($ipBinary === false || $subnetBinary === false || strlen($ipBinary) !== strlen($subnetBinary)) {
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
