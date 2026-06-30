<?php
namespace Mnb\SecurityCore\Web;

class SafeRedirector
{
    private bool $allowExternal;
    /** @var list<string> */
    private array $allowedHosts;
    private ?string $currentHost;

    /** @param array<string,mixed> $config */
    public function __construct(array $config = [], ?string $currentHost = null)
    {
        $this->allowExternal = (bool)($config['allow_external'] ?? false);
        $this->allowedHosts = array_values(array_filter(array_map('strtolower', array_map('strval', $config['allowed_hosts'] ?? []))));
        $this->currentHost = $currentHost !== null ? strtolower($currentHost) : null;
    }

    public function to(?string $target, string $fallback = '/'): string
    {
        $target = trim((string)($target ?? ''));
        if ($target === '' || !$this->isSafe($target)) {
            return $this->safeFallback($fallback);
        }
        return $target;
    }

    public function isSafe(string $target): bool
    {
        if ($target === '' || preg_match('/[\x00-\x1F\x7F\r\n]/', $target)) {
            return false;
        }
        $decoded = strtolower(rawurldecode($target));
        if (str_starts_with($decoded, 'javascript:') || str_starts_with($decoded, 'data:') || str_starts_with($decoded, 'vbscript:')) {
            return false;
        }
        if (str_starts_with($target, '//')) {
            return false;
        }
        if (str_starts_with($target, '/')) {
            return !str_starts_with($target, '/\\');
        }
        $parts = parse_url($target);
        if ($parts === false) {
            return false;
        }
        if (!isset($parts['scheme'])) {
            return false;
        }
        $scheme = strtolower((string)$parts['scheme']);
        if (!in_array($scheme, ['http', 'https'], true)) {
            return false;
        }
        $host = strtolower((string)($parts['host'] ?? ''));
        if ($host === '') {
            return false;
        }
        if ($this->currentHost !== null && hash_equals($this->currentHost, $host)) {
            return true;
        }
        return $this->allowExternal && in_array($host, $this->allowedHosts, true);
    }

    private function safeFallback(string $fallback): string
    {
        return str_starts_with($fallback, '/') && !str_starts_with($fallback, '//') ? $fallback : '/';
    }
}
