<?php
namespace Mnb\SecurityCore\Origin;

class ProxyProviderProfile
{
    public function __construct(private string $name, private array $headers = [], private array $notes = []) {}

    public static function named(string $name): self
    {
        $name = strtolower(trim($name));
        $profiles = [
            'cloudflare' => [['cf-connecting-ip','x-forwarded-for','x-forwarded-proto','x-forwarded-host'], ['Import Cloudflare IP ranges into trusted_proxy_ranges and firewall allow-list.']],
            'fastly' => [['fastly-client-ip','x-forwarded-for','x-forwarded-proto','x-forwarded-host'], ['Import Fastly edge ranges and block direct origin access.']],
            'aws_cloudfront' => [['x-forwarded-for','x-forwarded-proto','x-forwarded-host'], ['Use AWS managed prefix lists or exported ranges for origin firewalling.']],
            'aws_alb' => [['x-forwarded-for','x-forwarded-proto','x-forwarded-port'], ['Trust only ALB subnets/security groups.']],
            'nginx_reverse_proxy' => [['x-real-ip','x-forwarded-for','x-forwarded-proto','x-forwarded-host'], ['Set real_ip trusted ranges in nginx and pass sanitized headers.']],
            'apache_reverse_proxy' => [['x-forwarded-for','x-forwarded-proto','x-forwarded-host'], ['Use mod_remoteip with trusted proxy ranges.']],
            'custom' => [['forwarded','x-forwarded-for','x-forwarded-proto','x-forwarded-host','x-real-ip'], ['Define explicit trusted headers and proxy ranges.']],
        ];
        [$headers, $notes] = $profiles[$name] ?? $profiles['custom'];
        return new self($name ?: 'custom', $headers, $notes);
    }

    public function name(): string { return $this->name; }
    public function headers(): array { return $this->headers; }
    public function notes(): array { return $this->notes; }
    public function toArray(): array { return ['provider'=>$this->name,'trusted_headers'=>$this->headers,'notes'=>$this->notes]; }
}
