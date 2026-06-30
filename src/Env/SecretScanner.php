<?php
namespace Mnb\SecurityCore\Env;

class SecretScanner
{
    /** @var array<string,string> */
    private array $patterns = [
        'private_key' => '/-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/',
        'aws_key' => '/AKIA[0-9A-Z]{16}/',
        'generic_secret' => '/(api[_-]?key|secret|password|token)\s*=\s*["\']?[A-Za-z0-9_\-\/+=]{16,}/i',
        'bearer_token' => '/Authorization:\s*Bearer\s+[A-Za-z0-9._\-+=\/]{20,}/i',
    ];

    /** @param array<string,mixed> $policy */
    public function __construct(private array $policy = [])
    {
        if (is_array($policy['patterns'] ?? null)) {
            foreach ($policy['patterns'] as $name => $pattern) {
                if (is_string($name) && is_string($pattern) && $pattern !== '') {
                    $this->patterns[$name] = $pattern;
                }
            }
        }
    }

    /** @return array<int,array<string,mixed>> */
    public function scanDirectory(string $path, array $ignoreDirs = ['vendor', '.git', 'storage', 'demos', 'examples', 'tests', 'templates', 'node_modules']): array
    {
        $scanPolicy = is_array($this->policy['scanning'] ?? null) ? $this->policy['scanning'] : $this->policy;
        if (is_array($scanPolicy['ignore_paths'] ?? null)) {
            $ignoreDirs = array_values(array_unique(array_merge($ignoreDirs, array_map('strval', $scanPolicy['ignore_paths']))));
        }
        $allowPatterns = array_values(array_map('strval', is_array($scanPolicy['allow_patterns'] ?? null) ? $scanPolicy['allow_patterns'] : ['change-me', 'example', 'test-key']));
        $entropyEnabled = (bool)($scanPolicy['entropy'] ?? false);
        $findings = [];
        if (!is_dir($path)) {
            return [];
        }
        $iterator = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($path, \FilesystemIterator::SKIP_DOTS));
        foreach ($iterator as $file) {
            if (!$file->isFile()) {
                continue;
            }
            $full = $file->getPathname();
            foreach ($ignoreDirs as $ignore) {
                $ignore = trim((string)$ignore, '/\\');
                if ($ignore !== '' && (str_contains($full, DIRECTORY_SEPARATOR . $ignore . DIRECTORY_SEPARATOR) || str_ends_with($full, DIRECTORY_SEPARATOR . $ignore))) {
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
            foreach ($allowPatterns as $allow) {
                if ($allow !== '' && str_contains($content, $allow)) {
                    continue 2;
                }
            }
            foreach ($this->patterns as $name => $pattern) {
                if (preg_match($pattern, $content, $match, PREG_OFFSET_CAPTURE)) {
                    $findings[] = $this->finding($full, $name, $content, (int)$match[0][1], $this->severityFor($name));
                }
            }
            if ($entropyEnabled && preg_match_all('/[A-Za-z0-9_\-+=\/]{32,}/', $content, $matches, PREG_OFFSET_CAPTURE)) {
                foreach ($matches[0] as $match) {
                    $candidate = $match[0];
                    if ($this->entropy($candidate) >= 4.2) {
                        $findings[] = $this->finding($full, 'high_entropy_string', $content, (int)$match[1], 'medium');
                        break;
                    }
                }
            }
        }
        return $findings;
    }

    /** @return array<string,mixed> */
    public function report(string $path): array
    {
        $findings = $this->scanDirectory($path);
        return [
            'passed' => count($findings) === 0,
            'findings' => $findings,
            'summary' => [
                'total' => count($findings),
                'high' => count(array_filter($findings, fn(array $f): bool => ($f['severity'] ?? '') === 'high')),
                'medium' => count(array_filter($findings, fn(array $f): bool => ($f['severity'] ?? '') === 'medium')),
            ],
        ];
    }

    /** @return array<string,mixed> */
    private function finding(string $file, string $type, string $content, int $offset, string $severity): array
    {
        $line = substr_count(substr($content, 0, $offset), "\n") + 1;
        return ['file' => $file, 'type' => $type, 'severity' => $severity, 'line' => $line];
    }

    private function severityFor(string $name): string
    {
        return in_array($name, ['private_key', 'aws_key', 'bearer_token'], true) ? 'high' : 'medium';
    }

    private function entropy(string $value): float
    {
        $len = strlen($value);
        if ($len === 0) { return 0.0; }
        $freq = count_chars($value, 1);
        $entropy = 0.0;
        foreach ($freq as $count) {
            $p = $count / $len;
            $entropy -= $p * log($p, 2);
        }
        return $entropy;
    }
}
