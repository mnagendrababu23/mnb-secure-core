<?php
namespace Mnb\SecurityCore\Production;

use Mnb\SecurityCore\Web\OutputEncodingPolicy;

final class FinalProductionReadinessChecker
{
    /** @param array<string,mixed> $config */
    public function __construct(private array $config, private string $root = '') {}

    public function check(): ProductionReadinessReport
    {
        $policy = ProductionReadinessPolicy::fromConfig($this->config);
        $checks = [];
        $app = is_array($this->config['app'] ?? null) ? $this->config['app'] : [];
        $checks[] = $this->makeCheck('app_env_production', ($app['env'] ?? null) === 'production', 'high', 'Set APP_ENV=production for final deployment.');
        $checks[] = $this->makeCheck('debug_disabled', empty($app['debug']), 'critical', 'Set APP_DEBUG=false before release.');
        foreach ($policy->requiredSecrets() as $secret) {
            $value = getenv($secret) ?: ($_ENV[$secret] ?? '');
            $checks[] = $this->makeCheck('secret_' . strtolower($secret), is_string($value) && strlen($value) >= 32, 'high', $secret . ' must be configured with a 32+ character random value.');
        }
        $webhookSecret = (string)($this->config['request_receiving']['webhook']['secret'] ?? getenv('WEBHOOK_SECRET') ?: '');
        $checks[] = $this->makeCheck('webhook_secret_ready', !$policy->requireWebhookSecret() || strlen($webhookSecret) >= 32, 'high', 'Configure WEBHOOK_SECRET/request_receiving.webhook.secret for signed webhook verification.');
        $output = OutputEncodingPolicy::fromConfig($this->config);
        $checks[] = $this->makeCheck('xss_output_encoding_enabled', !$policy->requireXssEnforcement() || ($output->enabled() && $output->enforceByDefault()), 'high', 'Enable web_security.output_encoding.enforce_by_default.');
        $origin = is_array($this->config['origin_protection'] ?? null) ? $this->config['origin_protection'] : [];
        $checks[] = $this->makeCheck('origin_protection_enabled', !$policy->requireOriginGate() || !empty($origin['enabled']), 'high', 'Enable origin_protection for final release.');
        if ($this->root !== '') {
            foreach ($policy->requiredUpgradeManifests() as $manifest) {
                $checks[] = $this->makeCheck('manifest_' . preg_replace('/[^a-z0-9]+/i', '_', $manifest), is_file($this->root . '/' . $manifest), 'medium', $manifest . ' should exist for release traceability.');
            }
        }
        return new ProductionReadinessReport($checks);
    }

    private function makeCheck(string $id, bool $passed, string $level, string $message): array
    {
        return ['id' => $id, 'passed' => $passed, 'level' => $level, 'message' => $passed ? 'ok' : $message];
    }
}
