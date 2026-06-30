<?php
namespace Mnb\SecurityCore\Errors;

final class SafeErrorPageRenderer
{
    /** @param array<string,mixed> $payload */
    public function render(array $payload, int $status): string
    {
        $message = $this->e((string)($payload['message'] ?? 'Request failed.'));
        $code = $this->e((string)($payload['error']['code'] ?? 'ERROR'));
        $requestId = $this->e((string)($payload['error']['request_id'] ?? ''));
        $title = $this->titleForStatus($status);
        $debug = '';
        if (isset($payload['debug'])) {
            $debug = '<details style="margin-top:18px"><summary>Debug details</summary><pre style="white-space:pre-wrap;background:#f8fafc;border:1px solid #e5e7eb;padding:12px;border-radius:8px;">' . $this->e(json_encode($payload['debug'], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) ?: '') . '</pre></details>';
        }
        return '<!doctype html><html><head><meta charset="utf-8"><title>' . $this->e($title) . '</title><meta name="viewport" content="width=device-width,initial-scale=1"></head><body style="font-family:system-ui,-apple-system,Segoe UI,sans-serif;background:#f8fafc;color:#0f172a;padding:32px;"><main style="max-width:720px;margin:auto;background:white;border:1px solid #e5e7eb;border-radius:16px;padding:28px;"><h1 style="margin-top:0;">' . $this->e($title) . '</h1><p>' . $message . '</p><p><strong>Status:</strong> ' . $status . ' &nbsp; <strong>Code:</strong> ' . $code . '</p><p><strong>Reference:</strong> ' . $requestId . '</p>' . $debug . '</main></body></html>';
    }

    private function titleForStatus(int $status): string
    {
        return match ($status) {
            403 => 'Access denied',
            404 => 'Page not found',
            419 => 'Security check failed',
            422 => 'Validation failed',
            429 => 'Too many requests',
            503 => 'Service unavailable',
            default => 'Request failed',
        };
    }

    private function e(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
    }
}
