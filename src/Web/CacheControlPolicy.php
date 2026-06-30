<?php
namespace Mnb\SecurityCore\Web;

class CacheControlPolicy
{
    /** @param array<string,mixed> $profiles */
    public function __construct(private array $profiles = [])
    {
        $this->profiles = array_replace_recursive(self::defaultProfiles(), $profiles);
    }

    /** @return array<string,string> */
    public function headers(string $profile = 'private_user'): array
    {
        $config = $this->profiles[$profile] ?? $this->profiles['private_user'] ?? [];
        $cacheControl = (string)($config['cache_control'] ?? 'private, no-cache');
        $headers = ['Cache-Control' => $cacheControl];
        if (isset($config['pragma'])) {
            $headers['Pragma'] = (string)$config['pragma'];
        }
        if (isset($config['expires'])) {
            $headers['Expires'] = (string)$config['expires'];
        }
        if (isset($config['vary'])) {
            $headers['Vary'] = is_array($config['vary']) ? implode(', ', array_map('strval', $config['vary'])) : (string)$config['vary'];
        }
        return $headers;
    }

    /** @return array<string,array<string,mixed>> */
    public static function defaultProfiles(): array
    {
        return [
            'public_static' => ['cache_control' => 'public, max-age=31536000, immutable'],
            'public_api' => ['cache_control' => 'no-cache, public', 'vary' => ['Accept', 'Origin']],
            'private_user' => ['cache_control' => 'private, no-cache', 'vary' => ['Cookie', 'Authorization']],
            'sensitive_no_store' => ['cache_control' => 'no-store, private', 'pragma' => 'no-cache', 'expires' => '0'],
            'no_store' => ['cache_control' => 'no-store', 'pragma' => 'no-cache', 'expires' => '0'],
            'download' => ['cache_control' => 'private, no-store', 'pragma' => 'no-cache', 'expires' => '0'],
        ];
    }
}
