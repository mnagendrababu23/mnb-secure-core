<?php
namespace Mnb\SecurityCore\Monitoring;

class WebhookAlertChannel implements AlertChannelInterface
{
    public function __construct(private string $url, private int $timeoutSeconds = 2) {}

    public function send(array $alert): void
    {
        if (!filter_var($this->url, FILTER_VALIDATE_URL)) { return; }
        $payload = json_encode($alert, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        $context = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => "Content-Type: application/json\r\n",
                'content' => $payload,
                'timeout' => $this->timeoutSeconds,
                'ignore_errors' => true,
            ],
        ]);
        @file_get_contents($this->url, false, $context);
    }
}
