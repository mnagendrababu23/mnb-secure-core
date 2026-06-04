<?php
namespace Mnb\SecurityCore\Files;

class FileUploadPolicy
{
    public function __construct(
        public readonly array $allowedExtensions,
        public readonly array $allowedMimePrefixes,
        public readonly int $maxBytes,
        public readonly bool $denyDoubleExtensions = true,
        public readonly bool $randomizeNames = true
    ) {}

    public static function fromConfig(array $config, int $maxBytes): self
    {
        return new self(
            $config['allowed_extensions'] ?? [],
            $config['allowed_mime_prefixes'] ?? [],
            $maxBytes,
            (bool)($config['deny_double_extensions'] ?? true),
            (bool)($config['randomize_names'] ?? true)
        );
    }
}
