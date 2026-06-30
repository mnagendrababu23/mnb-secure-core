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
        public readonly string $responseFormat = 'json',
        public readonly ?ErrorPolicy $policy = null
    ) {}

    public static function fromRequest(Request $request, array $config = []): self
    {
        $policy = ErrorPolicy::fromConfig($config);
        $requestId = (string)($request->header('x-request-id') ?: self::generateRequestId());
        $format = $policy->responseFormat((string)$request->header('accept', ''));

        return new self(
            requestId: $requestId,
            environment: $policy->environment(),
            debug: $policy->debug(),
            responseFormat: in_array($format, ['json', 'html', 'text', 'problem_json'], true) ? $format : 'json',
            policy: $policy
        );
    }

    public static function generateRequestId(): string
    {
        return 'req_' . bin2hex(random_bytes(12));
    }

    public function shouldExposeDebug(): bool
    {
        return $this->policy ? $this->policy->shouldExposeDebug() : ($this->debug && $this->environment !== 'production');
    }

    /** @return array<string,mixed> */
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
