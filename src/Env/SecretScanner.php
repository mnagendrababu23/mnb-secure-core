<?php
namespace Mnb\SecurityCore\Env;

class SecretScanner
{
    private array $patterns = [
        'private_key' => '/-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/',
        'aws_key' => '/AKIA[0-9A-Z]{16}/',
        'generic_secret' => '/(api[_-]?key|secret|password|token)\s*=\s*["\']?[A-Za-z0-9_\-\/+=]{16,}/i',
    ];

    public function scanDirectory(string $path, array $ignoreDirs = ['vendor', '.git', 'storage', 'demos', 'examples', 'tests', 'templates', 'node_modules']): array
    {
        $findings = [];
        $iterator = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($path, \FilesystemIterator::SKIP_DOTS));
        foreach ($iterator as $file) {
            if (!$file->isFile()) {
                continue;
            }
            $full = $file->getPathname();
            foreach ($ignoreDirs as $ignore) {
                if (str_contains($full, DIRECTORY_SEPARATOR . $ignore . DIRECTORY_SEPARATOR)) {
                    continue 2;
                }
            }
            $baseName = basename($full);
            if (in_array($baseName, ['.env.example', 'env.example'], true) || str_ends_with($baseName, '.example')) {
                continue;
            }
            $content = @file_get_contents($full);
            if ($content === false || strlen($content) > 1024 * 1024) {
                continue;
            }
            foreach ($this->patterns as $name => $pattern) {
                if (preg_match($pattern, $content)) {
                    $findings[] = ['file' => $full, 'type' => $name];
                }
            }
        }
        return $findings;
    }
}
