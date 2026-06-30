<?php
namespace Mnb\SecurityCore\Env;

class SecretManager
{
    /** @param array<string,SecretDefinition> $definitions */
    public function __construct(
        private SecretProviderInterface $provider,
        private array $definitions,
        private ?KeyDeriver $deriver = null,
        private ?SecretRedactor $redactor = null,
        private bool $production = false,
        private array $config = []
    ) {}

    /** @param array<string,mixed> $config */
    public static function fromConfig(array $config, ?SecretProviderInterface $provider = null): self
    {
        $secrets = is_array($config['secrets'] ?? null) ? $config['secrets'] : [];
        $providerConfig = is_array($secrets['provider'] ?? null) ? $secrets['provider'] : [];
        $prefix = (string)($providerConfig['prefix'] ?? '');
        if ($provider === null) {
            $seed = $_ENV;
            foreach ($_SERVER as $key => $value) {
                if (is_string($key) && is_scalar($value) && !array_key_exists($key, $seed)) {
                    $seed[$key] = $value;
                }
            }
            if (!empty($config['app']['key']) && empty($seed['APP_KEY'])) {
                $seed['APP_KEY'] = (string)$config['app']['key'];
            }
            if (!empty($config['data_protection']['encryption']['keys']) && is_array($config['data_protection']['encryption']['keys'])) {
                $current = (string)($config['data_protection']['encryption']['current_key_id'] ?? array_key_first($config['data_protection']['encryption']['keys']));
                if (isset($config['data_protection']['encryption']['keys'][$current]) && empty($seed['DATA_KEY'])) {
                    $seed['DATA_KEY'] = (string)$config['data_protection']['encryption']['keys'][$current];
                }
            }
            if (!empty($config['data_protection']['search_hash']['key']) && empty($seed['DATA_SEARCH_HASH_KEY'])) {
                $seed['DATA_SEARCH_HASH_KEY'] = (string)$config['data_protection']['search_hash']['key'];
            }
            if (!empty($config['web_security']['signed_urls']['key']) && empty($seed['SIGNED_URL_KEY'])) {
                $seed['SIGNED_URL_KEY'] = (string)$config['web_security']['signed_urls']['key'];
            }
            $provider = new ArraySecretProvider($seed, 'env+config');
        }
        $definitionConfig = is_array($secrets['definitions'] ?? null) ? $secrets['definitions'] : self::defaultDefinitions();
        $definitions = [];
        foreach ($definitionConfig as $name => $definition) {
            if (is_array($definition)) {
                $definitions[(string)$name] = SecretDefinition::fromArray((string)$name, $definition);
            }
        }

        $redaction = is_array($secrets['redaction'] ?? null) ? $secrets['redaction'] : [];
        $redactor = new SecretRedactor(
            (string)($redaction['replacement'] ?? '[redacted]'),
            (int)($redaction['show_last'] ?? 0),
            array_keys($definitions)
        );

        $derivation = is_array($secrets['derivation'] ?? null) ? $secrets['derivation'] : [];
        $masterName = (string)($derivation['master'] ?? 'APP_KEY');
        $master = (string)($provider->get($masterName, $config['app']['key'] ?? ''));
        $deriver = $master !== '' ? new KeyDeriver($master, (string)($derivation['salt'] ?? 'mnb-secure-core')) : null;

        return new self($provider, $definitions, $deriver, $redactor, (string)($config['app']['env'] ?? '') === 'production', $secrets);
    }

    /** @return array<string,array<string,mixed>> */
    public static function defaultDefinitions(): array
    {
        return [
            'app.key' => ['env' => 'APP_KEY', 'required' => true, 'production_required' => true, 'min_length' => 32, 'purpose' => 'master application key', 'rotatable' => true],
            'data.key' => ['env' => 'DATA_KEY', 'required' => false, 'derive_from' => 'app.key', 'min_length' => 32, 'purpose' => 'data encryption', 'rotatable' => true],
            'data.search_hash_key' => ['env' => 'DATA_SEARCH_HASH_KEY', 'required' => false, 'derive_from' => 'app.key', 'min_length' => 32, 'purpose' => 'data search hashes / blind indexes', 'rotatable' => true],
            'signed_url.key' => ['env' => 'SIGNED_URL_KEY', 'required' => false, 'derive_from' => 'app.key', 'min_length' => 32, 'purpose' => 'signed URL HMAC', 'rotatable' => true],
            'webhook.secret' => ['env' => 'WEBHOOK_SECRET', 'required' => false, 'production_required' => false, 'min_length' => 32, 'purpose' => 'webhook HMAC verification', 'rotatable' => true],
            'cache.encryption_key' => ['env' => 'CACHE_ENCRYPTION_KEY', 'required' => false, 'derive_from' => 'app.key', 'min_length' => 32, 'purpose' => 'sensitive cache encryption', 'rotatable' => true],
            'backup.encryption_key' => ['env' => 'BACKUP_ENCRYPTION_KEY', 'required' => false, 'derive_from' => 'app.key', 'min_length' => 32, 'purpose' => 'backup encryption', 'rotatable' => true],
        ];
    }

    public function has(string $name): bool
    {
        return isset($this->definitions[$name]) && $this->provider->has($this->definitions[$name]->env());
    }

    public function get(string $name, mixed $default = null): mixed
    {
        $definition = $this->definition($name);
        if ($this->provider->has($definition->env())) {
            $value = $this->provider->get($definition->env(), $default);
            return $value === '' && $definition->deriveFrom() ? $this->deriveForDefinition($definition) : $value;
        }
        if ($definition->deriveFrom()) {
            return $this->deriveForDefinition($definition);
        }
        if ($definition->required() || ($this->production && $definition->productionRequired())) {
            throw new \RuntimeException('Required secret is missing: ' . $name);
        }
        return $default;
    }

    public function require(string $name): string
    {
        $value = (string)$this->get($name, '');
        if ($value === '') {
            throw new \RuntimeException('Required secret is empty: ' . $name);
        }
        return $value;
    }

    public function derive(string $purpose, int $bytes = 32): string
    {
        if ($this->deriver === null) {
            throw new \RuntimeException('Key derivation is unavailable because the master secret is missing.');
        }
        return $this->deriver->derive($purpose, $bytes);
    }

    public function inventory(): SecretInventory
    {
        return new SecretInventory($this->provider, $this->definitions, $this->production, $this->redactor);
    }

    public function rotationReport(): SecretRotationReport
    {
        $policy = new SecretRotationPolicy(is_array($this->config['rotation'] ?? null) ? $this->config['rotation'] : []);
        $items = [];
        foreach ($this->definitions as $definition) {
            $items[] = $policy->evaluate($definition);
        }
        return new SecretRotationReport($items);
    }

    public function redactor(): SecretRedactor
    {
        return $this->redactor ?: new SecretRedactor();
    }

    public function provider(): SecretProviderInterface
    {
        return $this->provider;
    }

    /** @return array<string,SecretDefinition> */
    public function definitions(): array
    {
        return $this->definitions;
    }

    public function definition(string $name): SecretDefinition
    {
        if (!isset($this->definitions[$name])) {
            throw new \InvalidArgumentException('Unknown secret definition: ' . $name);
        }
        return $this->definitions[$name];
    }

    private function deriveForDefinition(SecretDefinition $definition): string
    {
        if ($this->deriver === null) {
            return '';
        }
        return $this->deriver->derive('secret.' . $definition->name(), 32);
    }
}
