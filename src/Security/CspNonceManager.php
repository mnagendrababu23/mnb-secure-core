<?php
namespace Mnb\SecurityCore\Security;

class CspNonceManager
{
    public const REQUEST_ATTRIBUTE = 'mnb_csp_nonce';

    private ?string $nonce = null;

    public static function generate(int $bytes = 16): string
    {
        $bytes = max(16, $bytes);
        return rtrim(strtr(base64_encode(random_bytes($bytes)), '+/', '-_'), '=');
    }

    public function nonce(): string
    {
        if ($this->nonce === null) {
            $this->nonce = self::generate();
        }
        return $this->nonce;
    }

    public function value(): string
    {
        return $this->nonce();
    }

    public function attribute(): string
    {
        return $this->scriptAttribute();
    }

    public function scriptAttribute(): string
    {
        return 'nonce="' . htmlspecialchars($this->nonce(), ENT_QUOTES, 'UTF-8') . '"';
    }

    public function styleAttribute(): string
    {
        return $this->scriptAttribute();
    }
}
