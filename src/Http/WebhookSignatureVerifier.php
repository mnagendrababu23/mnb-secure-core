<?php
namespace Mnb\SecurityCore\Http;

class WebhookSignatureVerifier
{
    public function __construct(private array $config = []) {}

    /** @return array{valid:bool,reason:string} */
    public function verify(Request $request, string $rawBody): array
    {
        $secret = (string)($this->config['secret'] ?? '');
        if ($secret === '') {
            return ['valid' => false, 'reason' => 'missing_secret'];
        }

        $signatureHeader = (string)($this->config['signature_header'] ?? 'X-Signature');
        $timestampHeader = (string)($this->config['timestamp_header'] ?? 'X-Timestamp');
        $algorithm = strtolower((string)($this->config['algorithm'] ?? 'sha256'));
        if (!in_array($algorithm, hash_hmac_algos(), true)) {
            return ['valid' => false, 'reason' => 'unsupported_algorithm'];
        }

        $signature = $request->header($signatureHeader);
        if (!is_scalar($signature) || trim((string)$signature) === '') {
            return ['valid' => false, 'reason' => 'missing_signature'];
        }
        $signature = $this->normalizeSignature((string)$signature, $algorithm);

        $timestamp = $request->header($timestampHeader);
        $signedPayload = $rawBody;
        if (is_scalar($timestamp) && trim((string)$timestamp) !== '') {
            $timestamp = trim((string)$timestamp);
            $tolerance = (int)($this->config['tolerance_seconds'] ?? 300);
            if ($tolerance > 0 && ctype_digit($timestamp) && abs(time() - (int)$timestamp) > $tolerance) {
                return ['valid' => false, 'reason' => 'timestamp_outside_tolerance'];
            }
            $signedPayload = $timestamp . '.' . $rawBody;
        }

        $expected = hash_hmac($algorithm, $signedPayload, $secret);
        return hash_equals($expected, $signature)
            ? ['valid' => true, 'reason' => 'ok']
            : ['valid' => false, 'reason' => 'signature_mismatch'];
    }

    private function normalizeSignature(string $value, string $algorithm): string
    {
        $value = trim($value);
        foreach ([$algorithm . '=', 'v1=', 'sha256='] as $prefix) {
            if (str_starts_with(strtolower($value), strtolower($prefix))) {
                return substr($value, strlen($prefix));
            }
        }
        return $value;
    }
}
