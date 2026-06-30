<?php
namespace Mnb\SecurityCore\Web;

class SecureCookieBuilder
{
    /** @param array<string,mixed> $defaults */
    public function __construct(private array $defaults = []) {}

    /** @param array<string,mixed> $options */
    public function make(string $name, string $value, array $options = []): string
    {
        $options = array_replace($this->defaults, $options);
        $name = $this->validateName($name);
        $encodedValue = rawurlencode($value);
        $path = (string)($options['path'] ?? '/');
        $domain = isset($options['domain']) ? (string)$options['domain'] : null;
        $secure = (bool)($options['secure'] ?? true);
        $httpOnly = (bool)($options['http_only'] ?? $options['httponly'] ?? true);
        $sameSite = ucfirst(strtolower((string)($options['same_site'] ?? $options['samesite'] ?? 'Lax')));

        if (!in_array($sameSite, ['Lax', 'Strict', 'None'], true)) {
            throw new \InvalidArgumentException('SameSite must be Lax, Strict, or None.');
        }
        if ($sameSite === 'None' && !$secure) {
            throw new \InvalidArgumentException('SameSite=None cookies must use Secure.');
        }
        if (str_starts_with($name, '__Host-')) {
            if (!$secure || $path !== '/' || $domain !== null) {
                throw new \InvalidArgumentException('__Host- cookies require Secure, Path=/, and no Domain.');
            }
        }
        if (str_starts_with($name, '__Secure-') && !$secure) {
            throw new \InvalidArgumentException('__Secure- cookies require Secure.');
        }

        $parts = [$name . '=' . $encodedValue, 'Path=' . $this->sanitizeToken($path)];
        if ($domain !== null && trim($domain) !== '') {
            $parts[] = 'Domain=' . $this->sanitizeToken($domain);
        }
        if (isset($options['max_age'])) {
            $maxAge = (int)$options['max_age'];
            if ($maxAge < 0) {
                throw new \InvalidArgumentException('Cookie max_age must be zero or greater.');
            }
            $parts[] = 'Max-Age=' . $maxAge;
        }
        if (isset($options['expires'])) {
            $expires = is_int($options['expires']) ? gmdate('D, d M Y H:i:s \G\M\T', $options['expires']) : (string)$options['expires'];
            if (preg_match('/[\r\n]/', $expires)) {
                throw new \InvalidArgumentException('Cookie expires value is invalid.');
            }
            $parts[] = 'Expires=' . $expires;
        }
        if ($secure) { $parts[] = 'Secure'; }
        if ($httpOnly) { $parts[] = 'HttpOnly'; }
        $parts[] = 'SameSite=' . $sameSite;
        return implode('; ', $parts);
    }

    private function validateName(string $name): string
    {
        if ($name === '' || preg_match('/[^!#$%&\'*+\-.^_`|~0-9A-Za-z]/', $name)) {
            throw new \InvalidArgumentException('Cookie name contains invalid characters.');
        }
        return $name;
    }

    private function sanitizeToken(string $value): string
    {
        if ($value === '' || preg_match('/[\r\n;]/', $value)) {
            throw new \InvalidArgumentException('Cookie attribute contains invalid characters.');
        }
        return $value;
    }
}
