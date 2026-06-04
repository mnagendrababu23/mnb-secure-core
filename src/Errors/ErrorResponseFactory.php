<?php
namespace Mnb\SecurityCore\Errors;

use Mnb\SecurityCore\Http\Response;
use Throwable;

class ErrorResponseFactory
{
    public function __construct(private ExceptionMapper $mapper = new ExceptionMapper()) {}

    public function fromThrowable(Throwable $throwable, ErrorContext $context): Response
    {
        $mapped = $this->mapper->map($throwable);
        $payload = [
            'status' => false,
            'message' => $mapped['public_message'],
            'error' => [
                'code' => $mapped['error_code'],
                'request_id' => $context->requestId,
            ],
        ];

        if ($mapped['safe_details'] !== []) {
            $payload['error']['details'] = $mapped['safe_details'];
        }

        if ($context->shouldExposeDebug()) {
            $payload['debug'] = [
                'exception' => get_class($throwable),
                'message' => $throwable->getMessage(),
                'file' => $throwable->getFile(),
                'line' => $throwable->getLine(),
            ];
        }

        $headers = ['X-Request-Id' => $context->requestId];

        if ($context->responseFormat === 'html') {
            return Response::text($this->html($payload, $mapped['status']), $mapped['status'], array_merge($headers, [
                'Content-Type' => 'text/html; charset=UTF-8',
            ]));
        }

        if ($context->responseFormat === 'text') {
            return Response::text($payload['message'] . ' Reference: ' . $context->requestId, $mapped['status'], array_merge($headers, [
                'Content-Type' => 'text/plain; charset=UTF-8',
            ]));
        }

        return Response::json($payload, $mapped['status'], $headers);
    }

    public function logLevel(Throwable $throwable): string
    {
        return $this->mapper->map($throwable)['log_level'];
    }

    private function html(array $payload, int $status): string
    {
        $message = htmlspecialchars((string)$payload['message'], ENT_QUOTES, 'UTF-8');
        $code = htmlspecialchars((string)$payload['error']['code'], ENT_QUOTES, 'UTF-8');
        $requestId = htmlspecialchars((string)$payload['error']['request_id'], ENT_QUOTES, 'UTF-8');
        $debug = '';
        if (isset($payload['debug'])) {
            $debug = '<pre style="white-space:pre-wrap;background:#f8fafc;border:1px solid #e5e7eb;padding:12px;border-radius:8px;">' . htmlspecialchars(json_encode($payload['debug'], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), ENT_QUOTES, 'UTF-8') . '</pre>';
        }
        return '<!doctype html><html><head><meta charset="utf-8"><title>Error</title><meta name="viewport" content="width=device-width,initial-scale=1"></head><body style="font-family:system-ui,-apple-system,Segoe UI,sans-serif;background:#f8fafc;color:#0f172a;padding:32px;"><main style="max-width:720px;margin:auto;background:white;border:1px solid #e5e7eb;border-radius:16px;padding:28px;"><h1 style="margin-top:0;">Request failed</h1><p>' . $message . '</p><p><strong>Status:</strong> ' . $status . ' &nbsp; <strong>Code:</strong> ' . $code . '</p><p><strong>Reference:</strong> ' . $requestId . '</p>' . $debug . '</main></body></html>';
    }
}
