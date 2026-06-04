<?php
namespace Mnb\SecurityCore\Trust;

class DataBoundary
{
    public function __construct(
        public readonly string $zone,
        public readonly array $allowedDataClasses,
        public readonly array $allowedActions
    ) {}

    public function allows(string $dataClass, string $action): bool
    {
        return in_array($dataClass, $this->allowedDataClasses, true)
            && in_array($action, $this->allowedActions, true);
    }
}
