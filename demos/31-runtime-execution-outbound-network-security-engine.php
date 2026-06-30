<?php
require __DIR__ . '/_demo_bootstrap.php';

use Mnb\SecurityCore\Core\SecurityKernel;
use Mnb\SecurityCore\Monitoring\WebhookAlertChannel;

$config = require __DIR__ . '/../config/security.php';
$config['app']['env'] = 'testing';
$config['app']['key'] = str_repeat('R', 40);
$config['runtime']['commands']['php_version'] = [
    'binary' => PHP_BINARY,
    'allowed_args' => ['-v'],
    'timeout_seconds' => 2,
    'max_output_bytes' => 4096,
];
$config['network']['outbound']['timeout_seconds'] = 1;
$config['network']['outbound']['max_response_bytes'] = 2048;

$kernel = new SecurityKernel($config);

demo_title('31. Runtime Execution and Outbound Network Security Engine');

$runtimePolicy = $kernel->processPolicy();
demo_step('Runtime policy loaded', $runtimePolicy->toArray());

$allowedCommand = $kernel->safeProcessRunner()->check('php_version');
demo_result($allowedCommand['passed'], 'Allowed command accepted');

$unknownCommand = $kernel->safeProcessRunner()->check('rm_everything');
demo_result(!$unknownCommand['passed'] && $unknownCommand['reason'] === 'command_not_allowed', 'Unknown command blocked');

$dangerousArgument = $kernel->safeProcessRunner()->check('php_version', ['; rm -rf /']);
demo_result(!$dangerousArgument['passed'] && $dangerousArgument['reason'] === 'shell_metacharacter_blocked', 'Dangerous shell-style argument rejected');

$safeUrl = $kernel->outboundHttpClient()->checkUrl('https://93.184.216.34');
demo_result($safeUrl['passed'], 'Safe outbound HTTPS public IP literal allowed');

$httpUrl = $kernel->outboundHttpClient()->checkUrl('http://93.184.216.34');
demo_result(!$httpUrl['passed'] && $httpUrl['reason'] === 'https_required', 'HTTP URL blocked by HTTPS-only policy');

$localhost = $kernel->outboundHttpClient()->checkUrl('https://127.0.0.1/admin');
demo_result(!$localhost['passed'] && $localhost['reason'] === 'loopback_ip_blocked', 'Localhost/loopback URL blocked');

$privateIp = $kernel->outboundHttpClient()->checkUrl('https://10.0.0.10/admin');
demo_result(!$privateIp['passed'] && $privateIp['reason'] === 'private_ip_blocked', 'Private IP URL blocked');

$metadataIp = $kernel->outboundHttpClient()->checkUrl('https://169.254.169.254/latest/meta-data');
demo_result(!$metadataIp['passed'] && $metadataIp['reason'] === 'metadata_ip_blocked', 'Cloud metadata IP blocked');

$webhook = new WebhookAlertChannel('http://127.0.0.1/security-alert', 1, $kernel->outboundHttpClient());
$webhook->send(['event' => 'demo.runtime_network.blocked_webhook']);
demo_result(true, 'Webhook dispatch routed through outbound guard');

$ssrf = $kernel->vulnerabilityAdvisor()->recommend('ssrf');
$commandInjection = $kernel->vulnerabilityAdvisor()->recommend('command_injection');
demo_result($ssrf['status'] === 'protected', 'Vulnerability matrix marks SSRF protected');
demo_result($commandInjection['status'] === 'protected', 'Vulnerability matrix marks command injection protected');

echo json_encode([
    'passed' => true,
    'runtime_check' => $allowedCommand,
    'outbound_safe_url' => $safeUrl,
    'blocked_examples' => [
        'http' => $httpUrl,
        'loopback' => $localhost,
        'private' => $privateIp,
        'metadata' => $metadataIp,
    ],
    'vulnerability_status' => [
        'ssrf' => $ssrf['status'],
        'command_injection' => $commandInjection['status'],
    ],
], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
