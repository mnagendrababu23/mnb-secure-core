<?php
namespace Mnb\SecurityCore\Memory;

class ResourceScopeManager
{
    private array $scopes = [];
    public function start(string $name): ResourceScope
    {
        $scope = new ResourceScope($name);
        $this->scopes[] = $scope;
        return $scope;
    }
    public function cleanupAll(): array
    {
        return array_map(fn(ResourceScope $scope) => $scope->cleanup(), $this->scopes);
    }
}
