<?php
namespace Mnb\SecurityCore\Contracts;

interface TokenStoreInterface
{
    public function store(array $record): void;
    public function findByHash(string $tokenHash): ?array;
    public function revoke(string $tokenHash): void;
    public function revokeUserTokens(int|string $userId): void;
    public function touch(string $tokenHash, ?string $ip = null, ?string $userAgent = null): void;
}
