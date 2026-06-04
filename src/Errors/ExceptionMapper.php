<?php
namespace Mnb\SecurityCore\Errors;

use Mnb\SecurityCore\Exceptions\AppException;
use Mnb\SecurityCore\Exceptions\SecurityException;
use Mnb\SecurityCore\Exceptions\ValidationException;
use Throwable;

class ExceptionMapper
{
    /**
     * @return array{status:int,error_code:string,public_message:string,safe_details:array,log_level:string}
     */
    public function map(Throwable $throwable): array
    {
        if ($throwable instanceof AppException) {
            return [
                'status' => $throwable->statusCode(),
                'error_code' => $throwable->errorCode(),
                'public_message' => $throwable->publicMessage(),
                'safe_details' => $throwable->safeDetails(),
                'log_level' => $throwable->logLevel(),
            ];
        }

        if ($throwable instanceof ValidationException) {
            return [
                'status' => 422,
                'error_code' => 'VALIDATION_FAILED',
                'public_message' => 'Validation failed.',
                'safe_details' => ['errors' => $throwable->errors()],
                'log_level' => 'warning',
            ];
        }

        if ($throwable instanceof SecurityException) {
            return [
                'status' => 403,
                'error_code' => 'SECURITY_BLOCKED',
                'public_message' => 'This request was blocked for security reasons.',
                'safe_details' => [],
                'log_level' => 'warning',
            ];
        }

        return [
            'status' => 500,
            'error_code' => 'INTERNAL_ERROR',
            'public_message' => 'Something went wrong. Please try again later.',
            'safe_details' => [],
            'log_level' => 'error',
        ];
    }
}
