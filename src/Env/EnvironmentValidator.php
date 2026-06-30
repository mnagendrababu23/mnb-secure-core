<?php
namespace Mnb\SecurityCore\Env;

class EnvironmentValidator
{
    public function __construct(private array $config, private SecretManager $secrets) {}

    /** @return array<string,mixed> */
    public function validate(): array
    {
        $profile = EnvironmentProfile::fromConfig($this->config);
        $issues = [];
        $app = is_array($this->config['app'] ?? null) ? $this->config['app'] : [];
        if ($profile->isProduction()) {
            if (!empty($app['debug'])) {
                $issues[] = ['level' => 'high', 'key' => 'debug_enabled_in_production', 'message' => 'APP_DEBUG must be false in production.'];
            }
            if (empty($app['force_https'])) {
                $issues[] = ['level' => 'medium', 'key' => 'https_not_forced', 'message' => 'Production should force HTTPS.'];
            }
        }
        $secretReport = $this->secrets->inventory()->report()->toArray();
        foreach ($secretReport['items'] as $item) {
            if (($item['severity'] ?? '') === 'high') {
                $issues[] = ['level' => 'high', 'key' => 'secret_' . ($item['status'] ?? 'invalid'), 'message' => 'Secret ' . ($item['name'] ?? '?') . ' is ' . ($item['status'] ?? 'invalid') . '.'];
            }
        }
        return ['passed' => count(array_filter($issues, fn(array $i): bool => ($i['level'] ?? '') === 'high')) === 0, 'environment' => $profile->name(), 'issues' => $issues, 'secrets' => $secretReport];
    }
}
