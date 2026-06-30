<?php
namespace Mnb\SecurityCore\Network;

final class RedirectGuard
{
    public function __construct(private OutboundRequestPolicy $policy, private int $maxRedirects = 3) {}

    /** @param array<int,string> $chain @return array{passed:bool,reason:?string} */
    public function checkChain(array $chain): array
    {
        if (count($chain) > $this->maxRedirects) {
            return ['passed' => false, 'reason' => 'max_redirects_exceeded'];
        }
        foreach ($chain as $url) {
            $result = $this->policy->checkUrl((string)$url);
            if (!$result['passed']) {
                return ['passed' => false, 'reason' => 'redirect_' . (string)$result['reason']];
            }
        }
        return ['passed' => true, 'reason' => null];
    }

    public function absoluteUrl(string $baseUrl, string $location): string
    {
        $location = trim($location);
        if ($location === '') {
            return '';
        }
        if (preg_match('/^[a-z][a-z0-9+.-]*:\/\//i', $location)) {
            return $location;
        }
        $parts = parse_url($baseUrl);
        if (!is_array($parts) || empty($parts['scheme']) || empty($parts['host'])) {
            return $location;
        }
        $scheme = $parts['scheme'];
        $host = $parts['host'];
        $port = isset($parts['port']) ? ':' . $parts['port'] : '';
        if (str_starts_with($location, '//')) {
            return $scheme . ':' . $location;
        }
        if (str_starts_with($location, '/')) {
            return $scheme . '://' . $host . $port . $location;
        }
        $path = (string)($parts['path'] ?? '/');
        $dir = rtrim(str_replace('\\', '/', dirname($path)), '/');
        return $scheme . '://' . $host . $port . ($dir === '' ? '/' : $dir . '/') . $location;
    }
}
