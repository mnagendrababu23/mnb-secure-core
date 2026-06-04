<?php
namespace Mnb\SecurityCore\Exceptions;

use RuntimeException;
use Throwable;

class AppException extends RuntimeException
{
    public function __construct(
        string $internalMessage,
        private string $publicMessage = 'Something went wrong. Please try again later.',
        private int $statusCode = 500,
        private string $errorCode = 'APP_ERROR',
        private array $safeDetails = [],
        private string $logLevel = 'error',
        ?Throwable $previous = null
    ) {
        parent::__construct($internalMessage, 0, $previous);
    }

    public function publicMessage(): string
    {
        return $this->publicMessage;
    }

    public function statusCode(): int
    {
        return $this->statusCode;
    }

    public function errorCode(): string
    {
        return $this->errorCode;
    }

    public function safeDetails(): array
    {
        return $this->safeDetails;
    }

    public function logLevel(): string
    {
        return $this->logLevel;
    }
}
