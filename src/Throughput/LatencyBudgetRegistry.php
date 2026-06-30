<?php
namespace Mnb\SecurityCore\Throughput;

class LatencyBudgetRegistry
{
    /** @var array<string,LatencyBudget> */
    private array $budgets = [];

    public function register(string $name, LatencyBudget $budget): void
    {
        $this->budgets[$name] = $budget;
    }

    public function get(string $name): ?LatencyBudget
    {
        return $this->budgets[$name] ?? null;
    }

    public function all(): array
    {
        return $this->budgets;
    }
}
