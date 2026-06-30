<?php
namespace Mnb\SecurityCore\Web;

final class UnsafeOutputScanner
{
    public function __construct(private OutputEncodingPolicy $policy) {}

    /** @return array{passed:bool,count:int,findings:list<array<string,mixed>>} */
    public function scanString(string $content, string $source = 'inline'): array
    {
        $findings = [];
        $patterns = [
            'raw_php_echo' => '/<\?=\s*\$[A-Za-z_][A-Za-z0-9_]*(?!\s*\)|\s*->)/',
            'php_echo_variable' => '/echo\s+\$[A-Za-z_][A-Za-z0-9_]*\s*;/i',
            'dangerous_innerhtml' => '/\.innerHTML\s*=/i',
            'raw_unescaped_blade' => '/\{!!\s*[^!]+\s*!!\}/',
        ];
        foreach ($patterns as $type => $pattern) {
            if (preg_match_all($pattern, $content, $matches, PREG_OFFSET_CAPTURE)) {
                foreach ($matches[0] as $match) {
                    $findings[] = [
                        'type' => $type,
                        'source' => $source,
                        'offset' => $match[1],
                        'snippet' => substr($match[0], 0, 120),
                        'recommendation' => 'Use OutputEscaper, SafeTemplateRenderer, or framework escaping for untrusted data.',
                    ];
                }
            }
        }
        return ['passed' => count($findings) === 0, 'count' => count($findings), 'findings' => $findings];
    }

    /** @param list<string> $paths */
    public function scanFiles(array $paths): array
    {
        $all = [];
        foreach ($paths as $path) {
            if (is_file($path)) {
                $report = $this->scanString((string)file_get_contents($path), $path);
                array_push($all, ...$report['findings']);
            }
        }
        return ['passed' => count($all) === 0, 'count' => count($all), 'findings' => $all];
    }
}
