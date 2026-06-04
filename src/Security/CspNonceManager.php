<?php
namespace Mnb\SecurityCore\Security;

class CspNonceManager
{
    private ?string $nonce = null;

    public function nonce(): string
    {
        if ($this->nonce === null) {
            $this->nonce = rtrim(strtr(base64_encode(random_bytes(16)), '+/', '-_'), '=');
        }
        return $this->nonce;
    }

    public function attribute(): string
    {
        return 'nonce="' . htmlspecialchars($this->nonce(), ENT_QUOTES, 'UTF-8') . '"';
    }
}
