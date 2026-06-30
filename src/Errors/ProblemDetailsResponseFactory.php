<?php
namespace Mnb\SecurityCore\Errors;

use Throwable;

final class ProblemDetailsResponseFactory
{
    public function __construct(private ErrorCatalog $catalog = new ErrorCatalog()) {}

    /** @param array<string,mixed> $mapped */
    public function payload(Throwable $throwable, ErrorContext $context, array $mapped): array
    {
        $definition = $this->catalog->get((string)$mapped['error_code']);
        $payload = [
            'type' => $definition->type(),
            'title' => $definition->title(),
            'status' => (int)$mapped['status'],
            'code' => (string)$mapped['error_code'],
            'detail' => (string)$mapped['public_message'],
            'request_id' => $context->requestId,
        ];
        if (($mapped['safe_details'] ?? []) !== []) {
            $payload['details'] = $mapped['safe_details'];
        }
        if ($context->shouldExposeDebug()) {
            $payload['debug'] = [
                'exception' => get_class($throwable),
                'message' => $throwable->getMessage(),
            ];
        }
        return $payload;
    }
}
