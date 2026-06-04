<?php
namespace Mnb\SecurityCore\Http;

class Request
{
    public function __construct(
        private string $method,
        private string $path,
        private array $query = [],
        private array $body = [],
        private array $headers = [],
        private array $server = []
    ) {
        $this->headers = array_change_key_case($headers, CASE_LOWER);
    }

    public static function fromGlobals(): self
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
        return new self($_SERVER['REQUEST_METHOD'] ?? 'GET', $path, $_GET, $body, $headers, $_SERVER);
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
        return (!empty($this->server['HTTPS']) && $this->server['HTTPS'] !== 'off')
            || (($this->server['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
    }
    public function contentLength(): int { return (int)($this->server['CONTENT_LENGTH'] ?? 0); }
}
