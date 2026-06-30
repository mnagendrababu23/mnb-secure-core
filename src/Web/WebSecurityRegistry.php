<?php
namespace Mnb\SecurityCore\Web;

class WebSecurityRegistry
{
    /** @var array<string,WebSecurityProfile> */
    private array $profiles = [];

    /** @param array<string,mixed> $config */
    public function __construct(private array $config = [])
    {
        $profiles = is_array($config['profiles'] ?? null) ? $config['profiles'] : [];
        foreach ($profiles as $name => $profile) {
            if (is_string($name) && is_array($profile)) {
                $this->profiles[$name] = WebSecurityProfile::fromArray($name, $profile);
            }
        }
    }

    public static function fromConfig(array $config): self
    {
        return new self(is_array($config['web_security'] ?? null) ? $config['web_security'] : []);
    }

    public function get(string $name): WebSecurityProfile
    {
        if (!isset($this->profiles[$name])) {
            throw new \InvalidArgumentException("Web security profile '{$name}' is not configured.");
        }
        return $this->profiles[$name];
    }

    public function has(string $name): bool { return isset($this->profiles[$name]); }
    /** @return list<string> */ public function names(): array { return array_keys($this->profiles); }
}
