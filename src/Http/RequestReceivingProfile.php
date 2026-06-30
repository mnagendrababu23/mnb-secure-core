<?php
namespace Mnb\SecurityCore\Http;

class RequestReceivingProfile
{
    /** @param list<string> $methods @param list<string> $contentTypes */
    public function __construct(
        private string $name,
        private array $methods = [],
        private int $maxBytes = 0,
        private array $contentTypes = [],
        private ?string $ratePolicy = null,
        private ?string $auth = null,
        private bool $csrf = false,
        private bool $requestId = true,
        private bool $requestTrust = true,
        private bool $originProtection = true,
        private bool $https = true,
        private bool $trustedHost = true,
        private bool $cors = true,
        private bool $securityHeaders = true,
        private bool $jsonBody = true,
        private bool $suspiciousDetection = true,
        private bool $inputValidation = true,
        private bool $autoAudit = true,
        private ?string $trustBoundary = null,
        private ?string $uploadProfile = null,
        private array $options = []
    ) {
        self::assertName($name);
        $this->methods = self::normalizeMethods($methods);
        $this->contentTypes = self::normalizeList($contentTypes);
        if ($maxBytes < 0) {
            throw new \InvalidArgumentException('Request receiving max bytes must be zero or greater.');
        }
        $this->maxBytes = $maxBytes;
        if ($auth !== null && !in_array($auth, ['bearer', 'csrf', 'signature', 'none'], true)) {
            throw new \InvalidArgumentException('Request receiving auth must be bearer, csrf, signature, none, or null.');
        }
    }

    public static function fromArray(string $name, array $config): self
    {
        return new self(
            $name,
            self::listFrom($config['methods'] ?? []),
            (int)($config['max_bytes'] ?? 0),
            self::listFrom($config['content_types'] ?? []),
            isset($config['rate_policy']) && $config['rate_policy'] !== '' ? (string)$config['rate_policy'] : null,
            isset($config['auth']) && $config['auth'] !== null && $config['auth'] !== '' ? (string)$config['auth'] : null,
            (bool)($config['csrf'] ?? false),
            (bool)($config['request_id'] ?? true),
            (bool)($config['request_trust'] ?? true),
            (bool)($config['origin_protection'] ?? true),
            (bool)($config['https'] ?? true),
            (bool)($config['trusted_host'] ?? true),
            (bool)($config['cors'] ?? true),
            (bool)($config['security_headers'] ?? true),
            (bool)($config['json_body'] ?? true),
            (bool)($config['suspicious_detection'] ?? true),
            (bool)($config['input_validation'] ?? true),
            (bool)($config['auto_audit'] ?? true),
            isset($config['trust_boundary']) && $config['trust_boundary'] !== '' ? (string)$config['trust_boundary'] : null,
            isset($config['upload_profile']) && $config['upload_profile'] !== '' ? (string)$config['upload_profile'] : null,
            $config
        );
    }

    public function name(): string { return $this->name; }
    /** @return list<string> */ public function methods(): array { return $this->methods; }
    public function maxBytes(): int { return $this->maxBytes; }
    /** @return list<string> */ public function contentTypes(): array { return $this->contentTypes; }
    public function ratePolicy(): ?string { return $this->ratePolicy; }
    public function auth(): ?string { return $this->auth === 'none' ? null : $this->auth; }
    public function csrf(): bool { return $this->csrf; }
    public function requestId(): bool { return $this->requestId; }
    public function requestTrust(): bool { return $this->requestTrust; }
    public function originProtection(): bool { return $this->originProtection; }
    public function https(): bool { return $this->https; }
    public function trustedHost(): bool { return $this->trustedHost; }
    public function cors(): bool { return $this->cors; }
    public function securityHeaders(): bool { return $this->securityHeaders; }
    public function jsonBody(): bool { return $this->jsonBody; }
    public function suspiciousDetection(): bool { return $this->suspiciousDetection; }
    public function inputValidation(): bool { return $this->inputValidation; }
    public function autoAudit(): bool { return $this->autoAudit; }
    public function trustBoundary(): ?string { return $this->trustBoundary; }
    public function uploadProfile(): ?string { return $this->uploadProfile; }
    public function option(string $key, mixed $default = null): mixed { return $this->options[$key] ?? $default; }
    /** @return array<string,mixed> */ public function options(): array { return $this->options; }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return [
            'name' => $this->name,
            'methods' => $this->methods,
            'max_bytes' => $this->maxBytes,
            'content_types' => $this->contentTypes,
            'rate_policy' => $this->ratePolicy,
            'auth' => $this->auth(),
            'csrf' => $this->csrf,
            'request_id' => $this->requestId,
            'request_trust' => $this->requestTrust,
            'origin_protection' => $this->originProtection,
            'https' => $this->https,
            'trusted_host' => $this->trustedHost,
            'cors' => $this->cors,
            'security_headers' => $this->securityHeaders,
            'json_body' => $this->jsonBody,
            'suspicious_detection' => $this->suspiciousDetection,
            'input_validation' => $this->inputValidation,
            'auto_audit' => $this->autoAudit,
            'trust_boundary' => $this->trustBoundary,
            'upload_profile' => $this->uploadProfile,
        ];
    }

    /** @return list<string> */
    private static function listFrom(mixed $value): array
    {
        if (is_string($value)) {
            $value = explode(',', $value);
        }
        if (!is_array($value)) {
            return [];
        }
        return self::normalizeList($value);
    }

    /** @return list<string> */
    private static function normalizeList(array $items): array
    {
        $out = [];
        foreach ($items as $item) {
            if (!is_scalar($item)) { continue; }
            $item = trim((string)$item);
            if ($item !== '') { $out[] = $item; }
        }
        return array_values(array_unique($out));
    }

    /** @return list<string> */
    private static function normalizeMethods(array $methods): array
    {
        $methods = array_map(fn($m): string => strtoupper(trim((string)$m)), self::normalizeList($methods));
        foreach ($methods as $method) {
            if (!preg_match('/^[A-Z]{3,12}$/', $method)) {
                throw new \InvalidArgumentException('Request receiving method must be a safe HTTP token.');
            }
        }
        return $methods;
    }

    private static function assertName(string $name): void
    {
        if (!preg_match('/^[a-z][a-z0-9_.:-]{1,95}$/', $name)) {
            throw new \InvalidArgumentException('Request receiving profile name must be a safe slug.');
        }
    }
}
