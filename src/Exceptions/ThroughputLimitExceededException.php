<?php
namespace Mnb\SecurityCore\Exceptions;

class ThroughputLimitExceededException extends AppException
{
    public function __construct(
        string $internalMessage = 'Throughput or latency budget exceeded.',
        array $safeDetails = []
    ) {
        parent::__construct(
            $internalMessage,
            'The system is currently busy. Please retry after a short time.',
            503,
            'THROUGHPUT_LIMIT_EXCEEDED',
            $safeDetails,
            'warning'
        );
    }
}
