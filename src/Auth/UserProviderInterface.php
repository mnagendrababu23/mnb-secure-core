<?php
namespace Mnb\SecurityCore\Auth;

interface UserProviderInterface
{
    /** @return array<string,mixed>|null */
    public function findByIdentifier(string $identifier): ?array;

    /** @param array<string,mixed> $user */
    public function passwordHash(array $user): string;

    /** @param array<string,mixed> $user */
    public function userId(array $user): int|string;

    /** @param array<string,mixed> $user @return list<string> */
    public function roles(array $user): array;

    /** @param array<string,mixed> $user @return list<string> */
    public function permissions(array $user): array;

    /** @param array<string,mixed> $user @return list<string> */
    public function scopes(array $user): array;

    /** @param array<string,mixed> $user */
    public function isActive(array $user): bool;
}
