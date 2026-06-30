<?php
namespace Mnb\SecurityCore\Production;

final class ProductionReadinessPolicy
{
    /** @param array<string,mixed> $config */
    public function __construct(private array $config = []) {}

    /** @param array<string,mixed> $config */
    public static function fromConfig(array $config): self
    {
        $policy = is_array($config['production_readiness'] ?? null) ? $config['production_readiness'] : [];
        return new self($policy);
    }

    public function enabled(): bool { return (bool)($this->config['enabled'] ?? true); }
    public function blockOnHighIssues(): bool { return (bool)($this->config['block_on_high_issues'] ?? true); }
    public function requireWebhookSecret(): bool { return (bool)($this->config['require_webhook_secret'] ?? true); }
    public function requireXssEnforcement(): bool { return (bool)($this->config['require_xss_enforcement'] ?? true); }
    public function requireOriginGate(): bool { return (bool)($this->config['require_origin_gate'] ?? true); }
    public function requireReleaseManifest(): bool { return (bool)($this->config['require_release_manifest'] ?? true); }

    /** @return list<string> */
    public function requiredSecrets(): array
    {
        $defaults = ['APP_KEY', 'DATA_KEY', 'DATA_SEARCH_HASH_KEY', 'SIGNED_URL_KEY', 'WEBHOOK_SECRET'];
        return array_values(array_filter(array_map('strval', $this->config['required_secrets'] ?? $defaults)));
    }

    /** @return list<string> */
    public function requiredUpgradeManifests(): array
    {
        return array_values(array_filter(array_map('strval', $this->config['required_upgrade_manifests'] ?? [
            'UPGRADE-30-CHANGED-FILES-MANIFEST.md',
            'UPGRADE-31-CHANGED-FILES-MANIFEST.md',
            'UPGRADE-32-CHANGED-FILES-MANIFEST.md',
            'UPGRADE-33-CHANGED-FILES-MANIFEST.md',
            'UPGRADE-34-CHANGED-FILES-MANIFEST.md',
            'UPGRADE-35-CHANGED-FILES-MANIFEST.md',
        ])));
    }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return [
            'enabled' => $this->enabled(),
            'block_on_high_issues' => $this->blockOnHighIssues(),
            'require_webhook_secret' => $this->requireWebhookSecret(),
            'require_xss_enforcement' => $this->requireXssEnforcement(),
            'require_origin_gate' => $this->requireOriginGate(),
            'require_release_manifest' => $this->requireReleaseManifest(),
            'required_secrets' => $this->requiredSecrets(),
            'required_upgrade_manifests' => $this->requiredUpgradeManifests(),
        ];
    }
}
