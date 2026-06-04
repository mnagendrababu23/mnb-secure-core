<?php
namespace Mnb\SecurityCore\Trust;

class BoundaryGuard
{
    /** @var array<string,DataBoundary> */
    private array $boundaries = [];

    public function add(DataBoundary $boundary): void
    {
        $this->boundaries[$boundary->zone] = $boundary;
    }

    public function allows(string $zone, string $dataClass, string $action): bool
    {
        return isset($this->boundaries[$zone]) && $this->boundaries[$zone]->allows($dataClass, $action);
    }
}
