<?php
require __DIR__ . '/../autoload.php';

use Mnb\SecurityCore\Core\SecurityKernel;
use Mnb\SecurityCore\Vulnerability\VulnerabilityControlMapper;

$config = require __DIR__ . '/../config/security.php';
$config['app']['env'] = 'production';
$config['app']['debug'] = false;
$config['web_security']['output_encoding']['enabled'] = true;
$config['web_security']['output_encoding']['enforce_by_default'] = true;
$config['origin_protection']['enabled'] = true;
$config['request_receiving']['webhook']['secret'] = str_repeat('w', 32);

foreach (['APP_KEY','DATA_KEY','DATA_SEARCH_HASH_KEY','SIGNED_URL_KEY','WEBHOOK_SECRET'] as $secret) {
    $_ENV[$secret] = str_repeat(strtolower($secret[0] ?: 'x'), 32);
    putenv($secret . '=' . $_ENV[$secret]);
}

$kernel = new SecurityKernel($config);
$renderer = $kernel->safeTemplateRenderer();
$unsafe = '<img src=x onerror=alert(1)> Hello';
$rendered = $renderer->renderString('<h1>{{ title }}</h1><a href="{{ path|attr }}">Open</a>', [
    'title' => $unsafe,
    'path' => 'javascript:alert(1)',
]);
$scan = $kernel->unsafeOutputScanner()->scanString('<?= $userInput ?> <script>el.innerHTML = value</script>', 'demo-view.php');
$readiness = $kernel->finalProductionReadinessChecker(dirname(__DIR__))->check();
$gate = $kernel->finalReleaseGate()->evaluate($readiness);
$matrix = (new VulnerabilityControlMapper($config))->definitions();

$report = [
    'title' => 'MNB Secure Core v1.0.1 — Final Production Readiness, XSS Enforcement, and Release Consolidation Patch',
    'output_encoding_policy' => $kernel->outputEncodingPolicy()->toArray(),
    'rendered_safe_template' => $rendered,
    'unsafe_output_scan' => $scan,
    'env_checklist_count' => count($kernel->envChecklistBuilder()->build()['items']),
    'release_manifest' => $kernel->releaseConsolidationManifest()->toArray(),
    'release_archive_plan' => $kernel->releaseArchivePlanner()->plan(),
    'production_readiness' => $readiness->toArray(),
    'final_gate' => $gate,
    'matrix' => [
        'xss' => $matrix['xss']->status() ?? 'missing',
        'xss_template_escape_gap' => $matrix['xss_template_escape_gap']->status() ?? 'missing',
        'production_readiness_gap' => $matrix['production_readiness_gap']->status() ?? 'missing',
        'release_consolidation_gap' => $matrix['release_consolidation_gap']->status() ?? 'missing',
    ],
];

echo json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
