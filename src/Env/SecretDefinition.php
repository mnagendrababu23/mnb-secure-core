<?php
namespace Mnb\SecurityCore\Env;

class SecretDefinition
{
    /** @param array<string,mixed> $config */
    public function __construct(
        private string $name,
        private string $env,
        private bool $required = false,
        private bool $productionRequired = false,
        private int $minLength = 32,
        private string $purpose = '',
        private bool $rotatable = true,
        private ?string $deriveFrom = null,
        private bool $sensitive = true,
        private ?string $currentKeyId = null,
        private array $previousKeyIds = [],
        private ?string $createdAt = null
    ) {
        if (!preg_match('/^[A-Za-z0-9_.:-]{1,120}$/', $name)) {
            throw new \InvalidArgumentException('Secret definition name must be a safe identifier.');
        }
        if ($env === '' || !preg_match('/^[A-Z0-9_]{2,160}$/', $env)) {
            throw new \InvalidArgumentException('Secret environment key must use safe uppercase env syntax.');
        }
    }

    /** @param array<string,mixed> $config */
    public static function fromArray(string $name, array $config): self
    {
        return new self(
            $name,
            (string)($config['env'] ?? strtoupper(str_replace(['.', '-'], '_', $name))),
            (bool)($config['required'] ?? false),
            (bool)($config['production_required'] ?? false),
            (int)($config['min_length'] ?? 32),
            (string)($config['purpose'] ?? ''),
            (bool)($config['rotatable'] ?? true),
            isset($config['derive_from']) ? (string)$config['derive_from'] : null,
            (bool)($config['sensitive'] ?? true),
            isset($config['current_key_id']) ? (string)$config['current_key_id'] : null,
            array_values(array_map('strval', is_array($config['previous_key_ids'] ?? null) ? $config['previous_key_ids'] : [])),
            isset($config['created_at']) ? (string)$config['created_at'] : null
        );
    }

    public function name(): string { return $this->name; }
    public function env(): string { return $this->env; }
    public function required(): bool { return $this->required; }
    public function productionRequired(): bool { return $this->productionRequired; }
    public function minLength(): int { return $this->minLength; }
    public function purpose(): string { return $this->purpose; }
    public function rotatable(): bool { return $this->rotatable; }
    public function deriveFrom(): ?string { return $this->deriveFrom; }
    public function sensitive(): bool { return $this->sensitive; }
    public function currentKeyId(): ?string { return $this->currentKeyId; }
    /** @return array<int,string> */
    public function previousKeyIds(): array { return $this->previousKeyIds; }
    public function createdAt(): ?string { return $this->createdAt; }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return [
            'name' => $this->name,
            'env' => $this->env,
            'required' => $this->required,
            'production_required' => $this->productionRequired,
            'min_length' => $this->minLength,
            'purpose' => $this->purpose,
            'rotatable' => $this->rotatable,
            'derive_from' => $this->deriveFrom,
            'sensitive' => $this->sensitive,
            'current_key_id' => $this->currentKeyId,
            'previous_key_ids' => $this->previousKeyIds,
            'created_at' => $this->createdAt,
        ];
    }
}
