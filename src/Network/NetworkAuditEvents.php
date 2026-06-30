<?php
namespace Mnb\SecurityCore\Network;

final class NetworkAuditEvents
{
    public const OUTBOUND_ALLOWED = 'network.outbound.allowed';
    public const OUTBOUND_BLOCKED = 'network.outbound.blocked';
    public const OUTBOUND_FAILED = 'network.outbound.failed';
    public const OUTBOUND_REDIRECT_BLOCKED = 'network.outbound.redirect_blocked';
}
