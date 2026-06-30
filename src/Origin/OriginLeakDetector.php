<?php
namespace Mnb\SecurityCore\Origin;

class OriginLeakDetector
{
    public function __construct(private array $knownOriginHosts = [], private array $knownOriginIps = []) {}
    public static function fromConfig(array $config): self
    {
        $origin = is_array($config['origin_protection']['leak_detection'] ?? null) ? $config['origin_protection']['leak_detection'] : [];
        return new self((array)($origin['known_origin_hosts'] ?? []), (array)($origin['known_origin_ips'] ?? []));
    }
    /** @return array<int,OriginLeakFinding> */
    public function scanString(string $content, string $source = 'content'): array
    {
        $findings = [];
        foreach (OriginLeakPatternLibrary::patterns() as $type => $pattern) {
            if (preg_match_all($pattern, $content, $m)) {
                foreach (array_unique($m[0]) as $value) { $findings[] = new OriginLeakFinding($type, (string)$value, $type === 'private_ip_url' ? 'high' : 'medium', $source); }
            }
        }
        foreach ($this->knownOriginHosts as $host) {
            $host = (string)$host; if ($host !== '' && stripos($content, $host) !== false) { $findings[] = new OriginLeakFinding('known_origin_host', $host, 'high', $source); }
        }
        foreach ($this->knownOriginIps as $ip) {
            $ip = (string)$ip; if ($ip !== '' && str_contains($content, $ip)) { $findings[] = new OriginLeakFinding('known_origin_ip', $ip, 'high', $source); }
        }
        return $findings;
    }
    public function scanArray(array $values, string $source = 'config'): array
    {
        return $this->scanString(json_encode($values, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) ?: '', $source);
    }
    public function reportForString(string $content, string $source = 'content'): array
    {
        $findings = array_map(fn(OriginLeakFinding $f) => $f->toArray(), $this->scanString($content, $source));
        return ['passed'=>$findings === [], 'findings'=>$findings, 'count'=>count($findings)];
    }
}
