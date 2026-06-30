<?php
namespace Mnb\SecurityCore\Network;

final class DnsResolutionGuard
{
    public function __construct(private BlockedIpRangePolicy $ipPolicy) {}

    /** @return array{passed:bool,host:string,ips:array<int,string>,reason:?string} */
    public function check(string $host): array
    {
        $host = strtolower(trim($host, '[]'));
        if ($host === '') {
            return ['passed' => false, 'host' => $host, 'ips' => [], 'reason' => 'host_required'];
        }
        if (in_array($host, ['localhost', 'metadata.google.internal'], true)) {
            return ['passed' => false, 'host' => $host, 'ips' => [], 'reason' => $host === 'localhost' ? 'localhost_blocked' : 'metadata_host_blocked'];
        }

        $ips = [];
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            $ips[] = $host;
        } else {
            $v4 = function_exists('gethostbynamel') ? @gethostbynamel($host) : false;
            if (is_array($v4)) {
                $ips = array_merge($ips, $v4);
            }
            if (function_exists('dns_get_record')) {
                $records = @dns_get_record($host, DNS_AAAA);
                if (is_array($records)) {
                    foreach ($records as $record) {
                        if (!empty($record['ipv6']) && is_string($record['ipv6'])) {
                            $ips[] = $record['ipv6'];
                        }
                    }
                }
            }
        }

        $ips = array_values(array_unique(array_filter($ips, static fn($ip): bool => is_string($ip) && filter_var($ip, FILTER_VALIDATE_IP))));
        if ($ips === []) {
            return ['passed' => false, 'host' => $host, 'ips' => [], 'reason' => 'dns_resolution_failed'];
        }
        foreach ($ips as $ip) {
            $blocked = $this->ipPolicy->check($ip);
            if ($blocked['blocked']) {
                return ['passed' => false, 'host' => $host, 'ips' => $ips, 'reason' => $blocked['reason']];
            }
        }
        return ['passed' => true, 'host' => $host, 'ips' => $ips, 'reason' => null];
    }
}
