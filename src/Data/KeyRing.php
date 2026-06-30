<?php
namespace Mnb\SecurityCore\Data;

class KeyRing implements KeyProviderInterface
{
    public const PREFIX = 'mnbenc:';

    /** @param array<string,string> $keys */
    public function __construct(private string $currentKeyId, private array $keys)
    {
        if (!preg_match('/^[A-Za-z0-9_.:-]{1,80}$/', $currentKeyId)) {
            throw new \InvalidArgumentException('Current key id must be a safe identifier.');
        }
        if (!isset($keys[$currentKeyId])) {
            throw new \InvalidArgumentException('Current key id must exist in the key ring.');
        }
        foreach ($keys as $id => $key) {
            if (!is_string($id) || !preg_match('/^[A-Za-z0-9_.:-]{1,80}$/', $id)) {
                throw new \InvalidArgumentException('Key ids must be safe identifiers.');
            }
            if (!is_string($key) || strlen($key) < 32) {
                throw new \InvalidArgumentException('Data protection keys must be at least 32 characters.');
            }
        }
    }

    /** @param array<string,mixed> $config */
    public static function fromConfig(array $config, string $fallbackKey = ''): self
    {
        $encryption = is_array($config['encryption'] ?? null) ? $config['encryption'] : $config;
        $current = (string)($encryption['current_key_id'] ?? 'app-v1');
        $keys = is_array($encryption['keys'] ?? null) ? $encryption['keys'] : [];
        if ($keys === [] && $fallbackKey !== '') {
            $keys = [$current => $fallbackKey];
        }
        return new self($current, array_map('strval', $keys));
    }

    public function currentKeyId(): string
    {
        return $this->currentKeyId;
    }

    /** @return array<string,string> */
    public function keys(): array
    {
        return $this->keys;
    }

    public function encrypt(string $plain, string $aad = ''): string
    {
        $iv = random_bytes(12);
        $tag = '';
        $key = $this->deriveKey($this->keys[$this->currentKeyId]);
        $cipher = openssl_encrypt($plain, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, $aad);
        if ($cipher === false) {
            throw new \RuntimeException('Data encryption failed.');
        }

        $payload = [
            'v' => 1,
            'kid' => $this->currentKeyId,
            'alg' => 'AES-256-GCM',
            'iv' => base64_encode($iv),
            'tag' => base64_encode($tag),
            'ct' => base64_encode($cipher),
        ];

        return self::PREFIX . base64_encode(json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
    }

    public function decrypt(string $encoded, string $aad = ''): string
    {
        if (!str_starts_with($encoded, self::PREFIX)) {
            throw new \RuntimeException('Encrypted payload is missing the data-protection prefix.');
        }
        $json = base64_decode(substr($encoded, strlen(self::PREFIX)), true);
        if ($json === false) {
            throw new \RuntimeException('Invalid encrypted payload encoding.');
        }
        $payload = json_decode($json, true);
        if (!is_array($payload) || ($payload['v'] ?? null) !== 1 || ($payload['alg'] ?? null) !== 'AES-256-GCM') {
            throw new \RuntimeException('Unsupported encrypted payload format.');
        }
        $kid = (string)($payload['kid'] ?? '');
        if (!isset($this->keys[$kid])) {
            throw new \RuntimeException('Encrypted payload references an unknown key id.');
        }
        $iv = base64_decode((string)($payload['iv'] ?? ''), true);
        $tag = base64_decode((string)($payload['tag'] ?? ''), true);
        $cipher = base64_decode((string)($payload['ct'] ?? ''), true);
        if ($iv === false || $tag === false || $cipher === false || strlen($iv) !== 12 || strlen($tag) !== 16) {
            throw new \RuntimeException('Invalid encrypted payload parts.');
        }
        $plain = openssl_decrypt($cipher, 'aes-256-gcm', $this->deriveKey($this->keys[$kid]), OPENSSL_RAW_DATA, $iv, $tag, $aad);
        if ($plain === false) {
            throw new \RuntimeException('Data decryption failed.');
        }
        return $plain;
    }

    public function isEncrypted(mixed $value): bool
    {
        return is_string($value) && str_starts_with($value, self::PREFIX);
    }

    private function deriveKey(string $key): string
    {
        return hash('sha256', $key, true);
    }
}
