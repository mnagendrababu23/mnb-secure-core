<?php
namespace Mnb\SecurityCore\Exceptions;

use RuntimeException;

class ValidationException extends RuntimeException
{
    private array $errors;

    public function __construct(array $errors, string $message = 'Validation failed')
    {
        parent::__construct($message);
        $this->errors = $errors;
    }

    public function errors(): array
    {
        return $this->errors;
    }
}
