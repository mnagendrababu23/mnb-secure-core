<?php
namespace Mnb\SecurityCore\Errors;

use Mnb\SecurityCore\Exceptions\AppException;
use Mnb\SecurityCore\Exceptions\AuthorizationException;
use Mnb\SecurityCore\Exceptions\SecurityException;
use Mnb\SecurityCore\Exceptions\ValidationException;
use Throwable;

class ExceptionMapper
{
    public function __construct(
        private ErrorCatalog $catalog = new ErrorCatalog(),
        private ?ValidationErrorNormalizer $validationNormalizer = null
    ) {}

    /**
     * @return array{status:int,error_code:string,public_message:string,safe_details:array,log_level:string,title:string,type:string}
     */
    public function map(Throwable $throwable): array
    {
        if ($throwable instanceof ValidationException) {
            $definition = $this->catalog->get('VALIDATION_FAILED');
            $errors = $throwable->errors();
            if ($this->validationNormalizer) {
                $errors = $this->validationNormalizer->normalize($errors);
            }
            return $this->mapped($definition, ['errors' => $errors]);
        }

        if ($throwable instanceof AuthorizationException) {
            $definition = $this->catalog->get('FORBIDDEN');
            return $this->mapped($definition, [], $throwable->publicMessage(), $throwable->logLevel());
        }

        if ($throwable instanceof AppException) {
            $definition = $this->catalog->get($throwable->errorCode());
            return [
                'status' => $throwable->statusCode(),
                'error_code' => $throwable->errorCode(),
                'public_message' => $throwable->publicMessage(),
                'safe_details' => $throwable->safeDetails(),
                'log_level' => $throwable->logLevel(),
                'title' => $definition->title(),
                'type' => $definition->type(),
            ];
        }

        if ($throwable instanceof SecurityException) {
            return $this->mapped($this->catalog->get('SECURITY_BLOCKED'));
        }

        return $this->mapped($this->catalog->get('INTERNAL_ERROR'));
    }

    /** @return array{status:int,error_code:string,public_message:string,safe_details:array,log_level:string,title:string,type:string} */
    private function mapped(ErrorDefinition $definition, array $safeDetails = [], ?string $message = null, ?string $logLevel = null): array
    {
        return [
            'status' => $definition->status(),
            'error_code' => $definition->code(),
            'public_message' => $message ?? $definition->publicMessage(),
            'safe_details' => $safeDetails,
            'log_level' => $logLevel ?? $definition->logLevel(),
            'title' => $definition->title(),
            'type' => $definition->type(),
        ];
    }
}
