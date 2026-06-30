<?php
namespace Mnb\SecurityCore\Data;

class FieldProtector
{
    public function __construct(private DataProtectionRegistry $registry) {}

    /** @param array<string,mixed> $data @return array<string,mixed> */
    public function protectForStorage(string $resource, array $data): array
    {
        return $this->registry->protectForStorage($resource, $data);
    }

    /** @param array<string,mixed> $data @return array<string,mixed> */
    public function unprotectFromStorage(string $resource, array $data): array
    {
        return $this->registry->unprotectFromStorage($resource, $data);
    }
}
