<?php
namespace Mnb\SecurityCore\Monitoring;

use Mnb\SecurityCore\Network\OutboundHttpClient;
use Mnb\SecurityCore\Network\OutboundRequestPolicy;

class WebhookAlertChannel implements AlertChannelInterface
{
    public function __construct(
        private string $url,
        private int $timeoutSeconds = 2,
        private ?OutboundHttpClient $outboundHttpClient = null
    ) {}

    public function send(array $alert): void
    {
        if (!filter_var($this->url, FILTER_VALIDATE_URL)) {
            return;
        }

        $client = $this->outboundHttpClient ?: new OutboundHttpClient(new OutboundRequestPolicy(timeoutSeconds: $this->timeoutSeconds));
        $client->postJson($this->url, $alert);
    }
}
