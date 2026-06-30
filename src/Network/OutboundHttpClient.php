<?php
namespace Mnb\SecurityCore\Network;

use Mnb\SecurityCore\Logging\SecurityAuditEvent;
use Mnb\SecurityCore\Logging\SecurityAuditTrail;
use Throwable;

final class OutboundHttpClient
{
    public function __construct(private OutboundRequestPolicy $policy, private ?SecurityAuditTrail $audit = null) {}

    /** @return array<string,mixed> */
    public function checkUrl(string $url): array
    {
        return $this->policy->checkUrl($url);
    }

    /** @param array<string,string> $headers */
    public function get(string $url, array $headers = []): OutboundResponse
    {
        return $this->send(new OutboundRequest('GET', $url, $headers));
    }

    /** @param array<string,mixed> $payload @param array<string,string> $headers */
    public function postJson(string $url, array $payload, array $headers = []): OutboundResponse
    {
        $body = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($body === false) {
            return OutboundResponse::failed('json_encode_failed');
        }
        return $this->send(new OutboundRequest('POST', $url, ['Content-Type' => 'application/json'] + $headers, $body));
    }

    public function send(OutboundRequest $request): OutboundResponse
    {
        $redirects = [];
        $current = $request;
        $guard = new RedirectGuard($this->policy, $this->policy->maxRedirects());

        for ($hop = 0; $hop <= $this->policy->maxRedirects(); $hop++) {
            $check = $this->policy->checkUrl($current->url());
            if (!$check['passed']) {
                $this->audit(NetworkAuditEvents::OUTBOUND_BLOCKED, SecurityAuditEvent::OUTCOME_DENIED, SecurityAuditEvent::SEVERITY_WARNING, $current->url(), (string)$check['reason']);
                return OutboundResponse::deny((string)$check['reason']);
            }

            $response = $this->sendOnce($current);
            if ($response->blocked() || $response->statusCode() < 300 || $response->statusCode() >= 400) {
                $this->audit($response->successful() ? NetworkAuditEvents::OUTBOUND_ALLOWED : NetworkAuditEvents::OUTBOUND_FAILED, $response->successful() ? SecurityAuditEvent::OUTCOME_SUCCESS : SecurityAuditEvent::OUTCOME_FAILURE, $response->successful() ? SecurityAuditEvent::SEVERITY_INFO : SecurityAuditEvent::SEVERITY_WARNING, $current->url(), $response->error());
                return $response;
            }

            $location = $this->headerValue($response->headers(), 'Location');
            if ($location === null || $location === '') {
                return $response;
            }
            $nextUrl = $guard->absoluteUrl($current->url(), $location);
            $redirects[] = $nextUrl;
            $chainCheck = $guard->checkChain($redirects);
            if (!$chainCheck['passed']) {
                $this->audit(NetworkAuditEvents::OUTBOUND_REDIRECT_BLOCKED, SecurityAuditEvent::OUTCOME_DENIED, SecurityAuditEvent::SEVERITY_WARNING, $nextUrl, (string)$chainCheck['reason']);
                return OutboundResponse::deny((string)$chainCheck['reason']);
            }
            $current = new OutboundRequest('GET', $nextUrl, $request->headers());
        }

        $this->audit(NetworkAuditEvents::OUTBOUND_REDIRECT_BLOCKED, SecurityAuditEvent::OUTCOME_DENIED, SecurityAuditEvent::SEVERITY_WARNING, $current->url(), 'max_redirects_exceeded');
        return OutboundResponse::deny('max_redirects_exceeded');
    }

    private function sendOnce(OutboundRequest $request): OutboundResponse
    {
        $headers = $request->headers() + ['User-Agent' => $this->policy->userAgent()];
        $headerLines = [];
        foreach ($headers as $name => $value) {
            if (!preg_match('/^[A-Za-z0-9-]{1,80}$/', (string)$name) || preg_match('/[\r\n]/', (string)$value)) {
                return OutboundResponse::deny('unsafe_header_blocked');
            }
            $headerLines[] = $name . ': ' . $value;
        }

        $context = stream_context_create([
            'http' => [
                'method' => $request->method(),
                'header' => implode("\r\n", $headerLines),
                'content' => $request->body() ?? '',
                'timeout' => $this->policy->timeoutSeconds(),
                'ignore_errors' => true,
                'follow_location' => 0,
                'max_redirects' => 0,
            ],
        ]);

        try {
            $handle = @fopen($request->url(), 'rb', false, $context);
            if (!is_resource($handle)) {
                return OutboundResponse::failed('request_failed');
            }
            $body = stream_get_contents($handle, $this->policy->maxResponseBytes() + 1);
            $meta = stream_get_meta_data($handle);
            fclose($handle);
        } catch (Throwable $e) {
            return OutboundResponse::failed($e->getMessage());
        }

        $body = is_string($body) ? $body : '';
        $truncated = strlen($body) > $this->policy->maxResponseBytes();
        if ($truncated) {
            $body = substr($body, 0, $this->policy->maxResponseBytes());
        }
        $headers = is_array($meta['wrapper_data'] ?? null) ? $meta['wrapper_data'] : [];
        $status = $this->statusCode($headers);
        return new OutboundResponse($status >= 200 && $status < 300, $status, $body, $headers, $truncated ? 'max_response_bytes_exceeded' : null, false, $truncated);
    }

    /** @param array<int,string> $headers */
    private function statusCode(array $headers): int
    {
        foreach ($headers as $line) {
            if (preg_match('/^HTTP\/\S+\s+(\d{3})\b/', (string)$line, $m)) {
                return (int)$m[1];
            }
        }
        return 0;
    }

    /** @param array<int,string> $headers */
    private function headerValue(array $headers, string $name): ?string
    {
        foreach ($headers as $line) {
            if (str_contains($line, ':')) {
                [$header, $value] = explode(':', $line, 2);
                if (strcasecmp(trim($header), $name) === 0) {
                    return trim($value);
                }
            }
        }
        return null;
    }

    private function audit(string $event, string $outcome, string $severity, string $url, ?string $reason = null): void
    {
        if (!$this->audit) {
            return;
        }
        try {
            $parts = parse_url($url);
            $this->audit->record(SecurityAuditEvent::make('system', $event, $outcome, $severity, [], ['host' => $parts['host'] ?? null], ['reason' => $reason, 'url_fingerprint' => substr(hash('sha256', $url), 0, 16)]));
        } catch (Throwable) {
            // Audit must never break outbound deny/allow decisions.
        }
    }
}
