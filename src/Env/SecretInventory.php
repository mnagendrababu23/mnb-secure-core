<?php
namespace Mnb\SecurityCore\Env;

class SecretInventory
{
    /** @param array<string,SecretDefinition> $definitions */
    public function __construct(private SecretProviderInterface $provider, private array $definitions, private bool $production = false, private ?SecretRedactor $redactor = null) {}

    public function report(): SecretHealthReport
    {
        $items = [];
        foreach ($this->definitions as $name => $definition) {
            $present = $this->provider->has($definition->env());
            $value = $present ? (string)$this->provider->get($definition->env(), '') : '';
            $required = $definition->required() || ($this->production && $definition->productionRequired());
            $status = 'ok';
            $severity = 'info';
            if (!$present || $value === '') {
                $status = $definition->deriveFrom() ? 'derived' : 'missing';
                $severity = $required && !$definition->deriveFrom() ? 'high' : 'medium';
            } elseif (strlen($value) < $definition->minLength()) {
                $status = 'weak';
                $severity = $required || $this->production ? 'high' : 'medium';
            }
            $items[] = [
                'name' => $name,
                'env' => $definition->env(),
                'purpose' => $definition->purpose(),
                'source' => $present ? $this->provider->source() : ($definition->deriveFrom() ? 'derived:' . $definition->deriveFrom() : 'missing'),
                'present' => $present,
                'required' => $required,
                'min_length' => $definition->minLength(),
                'length' => $present ? strlen($value) : 0,
                'status' => $status,
                'severity' => $severity,
                'rotatable' => $definition->rotatable(),
                'current_key_id' => $definition->currentKeyId(),
                'previous_key_ids' => $definition->previousKeyIds(),
                'value' => $present && $this->redactor ? $this->redactor->redactValue($value) : null,
            ];
        }
        return new SecretHealthReport($items);
    }
}
