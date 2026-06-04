<?php
namespace Mnb\SecurityCore\Exceptions;

class BusinessRuleException extends AppException
{
    public function __construct(string $internalMessage, string $publicMessage = 'This action cannot be completed.', array $safeDetails = [])
    {
        parent::__construct($internalMessage, $publicMessage, 422, 'BUSINESS_RULE_FAILED', $safeDetails, 'warning');
    }
}
