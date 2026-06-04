<?php
namespace Mnb\SecurityCore\Errors;

use Mnb\SecurityCore\Http\Request;
use Throwable;

class ErrorContext
{
    public function __construct(
        public readonly string $requestId,
        public readonly string $environment = 'production',
        public readonly bool $debug = false,
        public readonly string $responseFormat = 'json'
    ) {}

    public static function fromRequest(Request $request, array $config = []): self
    {
        $errorConfig = $config['errors'] ?? [];
        $appConfig = $config['app'] ?? [];
        $requestId = (string)($request->header('x-request-id') ?: self::generateRequestId());
        $accept = strtolower((string)$request->header('accept', ''));
        $format = $errorConfig['response_format'] ?? 'auto';

        if ($format === 'auto') {
            $format = str_contains($accept, 'text/html') ? 'html' : 'json';
        }

        return new self(
            requestId: $requestId,
            environment: (string)($appConfig['env'] ?? 'production'),
            debug: (bool)($appConfig['debug'] ?? false),
            responseFormat: in_array($format, ['json', 'html', 'text'], true) ? $format : 'json'
        );
    }

    public static function generateRequestId(): string
    {
        return 'req_' . bin2hex(random_bytes(12));
    }

    public function shouldExposeDebug(): bool
    {
        return $this->debug && $this->environment !== 'production';
    }

    public function logContext(Throwable $throwable, array $extra = []): array
    {
        return array_merge([
            'request_id' => $this->requestId,
            'exception_class' => get_class($throwable),
            'exception_message' => $throwable->getMessage(),
            'file' => $throwable->getFile(),
            'line' => $throwable->getLine(),
        ], $extra);
    }
}
