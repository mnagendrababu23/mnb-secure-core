<?php
namespace Mnb\SecurityCore\Errors;

use Mnb\SecurityCore\Http\Response;
use Throwable;

class ErrorResponseFactory
{
    public function __construct(
        private ExceptionMapper $mapper = new ExceptionMapper(),
        private ?ProblemDetailsResponseFactory $problemFactory = null,
        private ?SafeErrorPageRenderer $pageRenderer = null
    ) {
        $this->problemFactory ??= new ProblemDetailsResponseFactory();
        $this->pageRenderer ??= new SafeErrorPageRenderer();
    }

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
            ];
            if (!$context->policy || $context->policy->includeFileLine()) {
                $payload['debug']['file'] = $throwable->getFile();
                $payload['debug']['line'] = $throwable->getLine();
            }
        }

        $headers = ['X-Request-Id' => $context->requestId];

        if ($context->responseFormat === 'problem_json') {
            return Response::text(json_encode($this->problemFactory->payload($throwable, $context, $mapped), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) ?: '{}', $mapped['status'], array_merge($headers, [
                'Content-Type' => 'application/problem+json; charset=UTF-8',
            ]));
        }

        if ($context->responseFormat === 'html') {
            return Response::text($this->pageRenderer->render($payload, $mapped['status']), $mapped['status'], array_merge($headers, [
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

    /** @return array<string,mixed> */
    public function map(Throwable $throwable): array
    {
        return $this->mapper->map($throwable);
    }
}
