<?php
namespace Mnb\SecurityCore\Errors;

final class ErrorCodeRegistry
{
    public function __construct(private ErrorCatalog $catalog = new ErrorCatalog()) {}

    public function isKnown(string $code): bool
    {
        return $this->catalog->has($code);
    }

    /** @return array<int,string> */
    public function codes(): array
    {
        return array_keys($this->catalog->all());
    }

    public function normalize(string $code): string
    {
        $code = strtoupper(preg_replace('/[^A-Z0-9_]+/', '_', $code) ?? 'INTERNAL_ERROR');
        return $this->isKnown($code) ? $code : 'INTERNAL_ERROR';
    }
}
