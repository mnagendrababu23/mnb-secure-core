<?php
namespace Mnb\SecurityCore\Web;

class SignedUrl
{
    public function __construct(private string $key, private int $defaultTtl = 900)
    {
        if (strlen($this->key) < 32) {
            throw new \InvalidArgumentException('Signed URL key must be at least 32 characters.');
        }
    }

    /** @param array<string,string|int|float|bool|null> $params */
    public function sign(string $path, array $params = [], ?int $expiresAt = null, string $purpose = 'default'): string
    {
        $this->assertSafePath($path);
        $params['expires'] = $expiresAt ?? (time() + $this->defaultTtl);
        $params['purpose'] = $purpose;
        ksort($params);
        $payload = $this->canonical($path, $params);
        $params['signature'] = hash_hmac('sha256', $payload, $this->key);
        return $path . '?' . http_build_query($params, '', '&', PHP_QUERY_RFC3986);
    }

    public function verify(string $url, string $purpose = 'default', ?int $now = null): bool
    {
        $parts = parse_url($url);
        if ($parts === false || empty($parts['path'])) {
            return false;
        }
        parse_str((string)($parts['query'] ?? ''), $params);
        $signature = (string)($params['signature'] ?? '');
        unset($params['signature']);
        if ($signature === '' || (string)($params['purpose'] ?? '') !== $purpose) {
            return false;
        }
        $expires = (int)($params['expires'] ?? 0);
        if ($expires <= ($now ?? time())) {
            return false;
        }
        ksort($params);
        $expected = hash_hmac('sha256', $this->canonical((string)$parts['path'], $params), $this->key);
        return hash_equals($expected, $signature);
    }

    /** @param array<string,mixed> $params */
    private function canonical(string $path, array $params): string
    {
        return $path . '?' . http_build_query($params, '', '&', PHP_QUERY_RFC3986);
    }

    private function assertSafePath(string $path): void
    {
        if ($path === '' || !str_starts_with($path, '/') || str_starts_with($path, '//') || preg_match('/[\x00-\x1F\x7F\r\n]/', $path)) {
            throw new \InvalidArgumentException('Signed URL path must be a safe absolute path.');
        }
    }
}
