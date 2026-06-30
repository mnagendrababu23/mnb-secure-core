<?php
namespace Mnb\SecurityCore\Origin;

class FirewallRuleAdvisor
{
    public function __construct(private array $config = []) {}
    public static function fromConfig(array $config): self { return new self($config); }
    public function plan(): OriginFirewallPlan
    {
        $origin = is_array($this->config['origin_protection'] ?? null) ? $this->config['origin_protection'] : [];
        $app = is_array($this->config['app'] ?? null) ? $this->config['app'] : [];
        $ranges = array_values(array_filter((array)($origin['trusted_proxy_ranges'] ?? $app['trusted_proxies'] ?? [])));
        $rules = ['Deny public HTTP/HTTPS access to the origin by default.', 'Allow SSH only from administrator IP ranges.', 'Do not expose database, cache, queue, or admin ports publicly.'];
        foreach ($ranges as $range) { $rules[] = 'Allow inbound HTTP/HTTPS from trusted proxy range: ' . $range; }
        if (!empty($origin['firewall']['generate_nginx_allow_deny'] ?? true)) { $rules[] = 'Nginx: add allow rules for trusted proxy ranges, then deny all.'; }
        if (!empty($origin['firewall']['generate_apache_require_ip'] ?? true)) { $rules[] = 'Apache: use Require ip for trusted proxy ranges and deny all others.'; }
        if (!empty($origin['firewall']['generate_ufw_plan'] ?? true)) { $rules[] = 'UFW: allow 80/443 from proxy ranges, deny 80/443 from anywhere else.'; }
        $warnings = $ranges === [] ? ['No trusted proxy ranges configured; firewall plan is advisory only.'] : [];
        return new OriginFirewallPlan($rules, $warnings);
    }
}
