<?php
namespace Mnb\SecurityCore\Exceptions;

class AuthorizationException extends AppException
{
    public function __construct(string $internalMessage = 'Authorization denied', string $publicMessage = 'You are not allowed to perform this action.')
    {
        parent::__construct($internalMessage, $publicMessage, 403, 'FORBIDDEN', [], 'warning');
    }
}
