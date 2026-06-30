<?php
namespace Mnb\SecurityCore\Origin;

class OriginLeakPatternLibrary
{
    public static function patterns(): array
    {
        return [
            'private_ip_url' => '~https?://(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3})(?::\d+)?[^\s"\']*~i',
            'localhost_url' => '~https?://(?:localhost|127\.0\.0\.1|\[::1\])(?::\d+)?[^\s"\']*~i',
            'internal_hostname' => '~\b(?:[a-z0-9-]+\.)*(?:internal|local|lan)\b~i',
            'raw_ip_url' => '~https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?[^\s"\']*~i',
        ];
    }
}
