<?php
namespace Mnb\SecurityCore\Files;

class FileUploadPolicy
{
    public function __construct(
        public readonly array $allowedExtensions,
        public readonly array $allowedMimePrefixes,
        public readonly int $maxBytes,
        public readonly bool $denyDoubleExtensions = true,
        public readonly bool $randomizeNames = true,
        public readonly array $blockedExtensions = ['php', 'phtml', 'phar', 'cgi', 'pl', 'sh', 'exe', 'com', 'bat', 'cmd', 'js', 'html', 'htm', 'svg'],
        public readonly int $maxOriginalNameLength = 180,
        public readonly bool $rejectExecutableContent = true,
        public readonly array $mimeByExtension = []
    ) {}

    public static function fromConfig(array $config, int $maxBytes): self
    {
        return new self(
            $config['allowed_extensions'] ?? [],
            $config['allowed_mime_prefixes'] ?? [],
            $maxBytes,
            (bool)($config['deny_double_extensions'] ?? true),
            (bool)($config['randomize_names'] ?? true),
            $config['blocked_extensions'] ?? ['php', 'phtml', 'phar', 'cgi', 'pl', 'sh', 'exe', 'com', 'bat', 'cmd', 'js', 'html', 'htm', 'svg'],
            (int)($config['max_original_name_length'] ?? 180),
            (bool)($config['reject_executable_content'] ?? true),
            $config['mime_by_extension'] ?? []
        );
    }
}
