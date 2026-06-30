<?php
namespace Mnb\SecurityCore\Recovery;

class BackupSigner
{
    public function __construct(private string $key) {}

    public function sign(string $payload): string
    {
        return hash_hmac('sha256', $payload, $this->keyMaterial());
    }

    public function verify(string $payload, string $signature): bool
    {
        return hash_equals($this->sign($payload), $signature);
    }

    private function keyMaterial(): string
    {
        return hash('sha256', $this->key !== '' ? $this->key : 'mnb-secure-core-backup-signing-key', true);
    }
}
