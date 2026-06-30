<?php
namespace Mnb\SecurityCore\Origin;

use Mnb\SecurityCore\Http\RequestTrust;

class ProxyIpRangeSet
{
    public function __construct(private array $ranges = [])
    {
        $this->ranges = array_values(array_filter(array_map('trim', array_map('strval', $ranges))));
    }

    public function ranges(): array { return $this->ranges; }
    public function invalidRanges(): array
    {
        return array_values(array_filter($this->ranges, fn(string $range) => !$this->isValid($range)));
    }
    public function contains(string $ip): bool { return RequestTrust::isTrustedProxy($ip, $this->ranges); }
    public function isValid(string $range): bool
    {
        if ($range === '*') { return true; }
        if (str_contains($range, '/')) {
            [$ip, $mask] = explode('/', $range, 2);
            return filter_var($ip, FILTER_VALIDATE_IP) !== false && ctype_digit($mask) && (int)$mask >= 0 && (int)$mask <= (str_contains($ip, ':') ? 128 : 32);
        }
        return filter_var($range, FILTER_VALIDATE_IP) !== false;
    }
    public function toArray(): array { return ['ranges'=>$this->ranges,'invalid_ranges'=>$this->invalidRanges()]; }
}
