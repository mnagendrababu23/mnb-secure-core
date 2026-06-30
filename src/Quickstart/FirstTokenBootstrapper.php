<?php
namespace Mnb\SecurityCore\Quickstart;

use Mnb\SecurityCore\Auth\OpaqueTokenService;
use Mnb\SecurityCore\Core\SecurityKernel;

class FirstTokenBootstrapper
{
    public function __construct(
        private array $config,
        private string $projectRoot
    ) {}

    /**
     * @param array{
     *     user_id?: int|string,
     *     name?: string,
     *     email?: string,
     *     role?: string,
     *     scopes?: array<int,string>,
     *     ttl_seconds?: int,
     *     device_id?: string,
     *     device_name?: string,
     *     write_demo_user?: bool,
     *     demo_user_file?: string|null
     * } $options
     * @return array<string,mixed>
     */
    public function issue(array $options = []): array
    {
        $userId = $options['user_id'] ?? 'demo-admin';
        if (!is_int($userId) && !is_string($userId)) {
            throw new \InvalidArgumentException('Bootstrap user_id must be an integer or string.');
        }
        $userId = is_string($userId) ? trim($userId) : $userId;
        if ($userId === '') {
            throw new \InvalidArgumentException('Bootstrap user_id cannot be empty.');
        }

        $scopes = $this->normalizeScopes($options['scopes'] ?? ['admin:*', 'profile.read', 'uploads.write']);
        $ttlSeconds = (int)($options['ttl_seconds'] ?? 86400);
        if ($ttlSeconds < 60) {
            throw new \InvalidArgumentException('Bootstrap token ttl_seconds must be at least 60.');
        }

        $deviceId = trim((string)($options['device_id'] ?? 'quickstart-cli'));
        $deviceName = trim((string)($options['device_name'] ?? 'MNB Secure Core Quickstart'));

        $kernel = new SecurityKernel($this->config);
        $tokens = new OpaqueTokenService($kernel->tokenStore(), $kernel->auditTrail());
        $issued = $tokens->issue($userId, $scopes, $deviceId ?: null, $deviceName ?: null, $ttlSeconds);
        $record = $issued['record'];

        $user = [
            'id' => $userId,
            'name' => trim((string)($options['name'] ?? 'Demo Admin')),
            'email' => trim((string)($options['email'] ?? 'demo-admin@example.test')),
            'role' => trim((string)($options['role'] ?? 'admin')),
            'scopes' => $scopes,
            'created_for' => 'mnb-secure-core-v1.0.1-quickstart',
        ];

        $files = [
            'token_store' => $this->relativePath((string)($this->config['paths']['tokens'] ?? 'storage/tokens/tokens.json')),
            'audit_log' => $this->relativePath((string)($this->config['audit']['file'] ?? 'storage/audit/security-audit.log')),
            'demo_user' => null,
        ];

        if (!empty($options['write_demo_user'])) {
            $demoUserFile = $this->resolvePath((string)($options['demo_user_file'] ?? ($this->projectRoot . DIRECTORY_SEPARATOR . 'storage' . DIRECTORY_SEPARATOR . 'private' . DIRECTORY_SEPARATOR . 'demo-user.json')));
            $dir = dirname($demoUserFile);
            if (!is_dir($dir) && !mkdir($dir, 0775, true) && !is_dir($dir)) {
                throw new \RuntimeException('Unable to create demo user directory: ' . $dir);
            }
            file_put_contents($demoUserFile, json_encode($user, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
            $files['demo_user'] = $this->relativePath($demoUserFile);
        }

        return [
            'ok' => true,
            'version' => 'v1.0.1',
            'warning' => 'The plain token is shown once. Store it securely and do not commit it.',
            'user' => $user,
            'token' => [
                'plain_token' => $issued['plain_token'],
                'authorization_header' => 'Authorization: Bearer ' . $issued['plain_token'],
                'expires_at' => gmdate('c', (int)$record['expires_at']),
                'ttl_seconds' => $ttlSeconds,
                'scopes' => $scopes,
                'device_id' => $deviceId ?: null,
                'device_name' => $deviceName ?: null,
            ],
            'files' => $files,
            'next_steps' => [
                'Add the authorization_header value to API requests.',
                'Run php bin/mnb-secure doctor before deploying.',
                'Revoke and rotate this bootstrap token after creating real users/admins.',
            ],
        ];
    }

    /** @param mixed $scopes @return array<int,string> */
    private function normalizeScopes(mixed $scopes): array
    {
        if (is_string($scopes)) {
            $scopes = array_filter(array_map('trim', explode(',', $scopes)));
        }
        if (!is_array($scopes)) {
            throw new \InvalidArgumentException('Bootstrap scopes must be an array or comma-separated string.');
        }

        $normalized = [];
        foreach ($scopes as $scope) {
            if (!is_scalar($scope)) {
                throw new \InvalidArgumentException('Bootstrap scopes must contain only strings.');
            }
            $scope = trim((string)$scope);
            if ($scope === '') {
                continue;
            }
            if (!preg_match('/^[A-Za-z0-9_.:*\-]+$/', $scope)) {
                throw new \InvalidArgumentException('Unsafe bootstrap scope: ' . $scope);
            }
            $normalized[] = $scope;
        }

        $normalized = array_values(array_unique($normalized));
        if ($normalized === []) {
            throw new \InvalidArgumentException('At least one bootstrap scope is required.');
        }

        return $normalized;
    }

    private function resolvePath(string $path): string
    {
        $path = trim($path);
        if ($path === '') {
            throw new \InvalidArgumentException('Bootstrap path cannot be empty.');
        }
        if ($this->isAbsolutePath($path)) {
            return $path;
        }
        return rtrim($this->projectRoot, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $path;
    }

    private function relativePath(string $path): string
    {
        $resolved = $this->resolvePath($path);
        $root = rtrim($this->projectRoot, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
        return str_starts_with($resolved, $root) ? substr($resolved, strlen($root)) : $resolved;
    }

    private function isAbsolutePath(string $path): bool
    {
        if (str_starts_with($path, '/')) {
            return true;
        }

        return strlen($path) >= 3
            && ctype_alpha($path[0])
            && $path[1] === ':'
            && ($path[2] === '\\' || $path[2] === '/');
    }
}
