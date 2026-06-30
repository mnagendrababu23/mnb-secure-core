<?php
namespace Mnb\SecurityCore\Origin;

final class OriginAuditEvents
{
    public const DIRECT_IP_HOST_BLOCKED = 'origin.direct_ip_host_blocked';
    public const UNTRUSTED_FORWARDED_HEADERS_BLOCKED = 'origin.untrusted_forwarded_headers_blocked';
    public const UNTRUSTED_HOST_BLOCKED = 'origin.untrusted_host_blocked';
    public const IDENTITY_HEADERS_STRIPPED = 'origin.identity_headers_stripped';
    public const PROXY_REQUIRED_BLOCKED = 'origin.proxy_required_blocked';
    public const EXPOSURE_SCAN_COMPLETED = 'origin.exposure_scan_completed';
    public const FIREWALL_PLAN_GENERATED = 'origin.firewall_plan_generated';
}
