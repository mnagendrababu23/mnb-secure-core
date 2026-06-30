<?php
namespace Mnb\SecurityCore\Env;

class KeyDeriver
{
    public function __construct(private string $masterKey, private string $salt = 'mnb-secure-core')
    {
        if ($masterKey === '') {
            throw new \InvalidArgumentException('Master key is required for key derivation.');
        }
    }

    public function derive(string $purpose, int $bytes = 32, bool $raw = false): string
    {
        if ($purpose === '' || strlen($purpose) > 200) {
            throw new \InvalidArgumentException('Key derivation purpose must be a non-empty short string.');
        }
        $length = max(16, min(64, $bytes));
        if (function_exists('hash_hkdf')) {
            $derived = hash_hkdf('sha256', $this->masterKey, $length, 'mnb:' . $purpose, $this->salt);
            return $raw ? $derived : bin2hex($derived);
        }
        $blocks = '';
        $counter = 1;
        while (strlen($blocks) < $length) {
            $blocks .= hash_hmac('sha256', $this->salt . '|' . $purpose . '|' . $counter, $this->masterKey, true);
            $counter++;
        }
        $derived = substr($blocks, 0, $length);
        return $raw ? $derived : bin2hex($derived);
    }
}
