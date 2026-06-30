<?php
namespace Mnb\SecurityCore\Http;

class RequestReceivingRegistry
{
    /** @var array<string,RequestReceivingProfile> */
    private array $profiles = [];

    /** @param array<string,RequestReceivingProfile|array<string,mixed>> $profiles */
    public function __construct(array $profiles = [])
    {
        foreach ($profiles as $name => $profile) {
            if ($profile instanceof RequestReceivingProfile) {
                $this->profiles[$profile->name()] = $profile;
                continue;
            }
            if (is_array($profile)) {
                $this->profiles[(string)$name] = RequestReceivingProfile::fromArray((string)$name, $profile);
            }
        }
    }

    public static function fromConfig(array $config): self
    {
        $receiving = is_array($config['request_receiving'] ?? null) ? $config['request_receiving'] : [];
        $defaults = is_array($receiving['defaults'] ?? null) ? $receiving['defaults'] : [];
        $profiles = is_array($receiving['profiles'] ?? null) ? $receiving['profiles'] : [];
        $merged = [];
        foreach ($profiles as $name => $profile) {
            if (is_array($profile)) {
                $merged[$name] = array_replace($defaults, $profile);
            }
        }
        return new self($merged);
    }

    public function has(string $name): bool
    {
        return isset($this->profiles[$name]);
    }

    public function get(string $name): RequestReceivingProfile
    {
        if (!$this->has($name)) {
            throw new \InvalidArgumentException("Request receiving profile '{$name}' is not configured.");
        }
        return $this->profiles[$name];
    }

    /** @return array<string,RequestReceivingProfile> */
    public function all(): array
    {
        return $this->profiles;
    }
}
