<?php
namespace Mnb\SecurityCore\Exceptions;

class NotFoundException extends AppException
{
    public function __construct(string $internalMessage = 'Resource not found', string $publicMessage = 'The requested record was not found.')
    {
        parent::__construct($internalMessage, $publicMessage, 404, 'NOT_FOUND', [], 'warning');
    }
}
