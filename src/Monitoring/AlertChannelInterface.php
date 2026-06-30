<?php
namespace Mnb\SecurityCore\Monitoring;

interface AlertChannelInterface
{
    /** @param array<string,mixed> $alert */
    public function send(array $alert): void;
}
