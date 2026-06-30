<?php
namespace Mnb\SecurityCore\Trust;

class BoundaryGuard
{
    /** @var array<string,list<DataBoundary>> */
    private array $boundaries = [];

    public function add(DataBoundary $boundary): void
    {
        $this->boundaries[$boundary->zone] ??= [];
        $this->boundaries[$boundary->zone][] = $boundary;
    }

    public function allows(string $zone, string $dataClass, string $action): bool
    {
        foreach ($this->boundaries[$zone] ?? [] as $boundary) {
            if ($boundary->allows($dataClass, $action)) {
                return true;
            }
        }
        return false;
    }
}
