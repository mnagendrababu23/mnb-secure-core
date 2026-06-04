<?php
namespace Mnb\SecurityCore\Exceptions;

class MemoryLimitExceededException extends AppException
{
    public function __construct(
        string $internalMessage = 'Memory budget exceeded.',
        array $safeDetails = []
    ) {
        parent::__construct(
            $internalMessage,
            'The request needs more resources than allowed. Please reduce the data size or try a smaller export/import.',
            503,
            'MEMORY_LIMIT_EXCEEDED',
            $safeDetails,
            'warning'
        );
    }
}
