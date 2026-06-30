<?php
require_once __DIR__ . '/_demo_bootstrap.php';

use Mnb\SecurityCore\Env\EnvLoader;
use Mnb\SecurityCore\Env\SecretScanner;
use Mnb\SecurityCore\Security\ProductionSecurityChecker;

demo_title('10. Environment and Secret Management');

$envFile = demo_storage_path('env-demo/.env');
file_put_contents($envFile, "APP_ENV=production\nAPP_DEBUG=false\nAPP_KEY=1234567890123456789012345678901234567890\nFORCE_HTTPS=true\n");
EnvLoader::load($envFile);

demo_step('Loaded APP_ENV', EnvLoader::get('APP_ENV'));
demo_step('Loaded FORCE_HTTPS', EnvLoader::get('FORCE_HTTPS'));

$config = [
    'app' => ['env' => 'production', 'debug' => false, 'force_https' => true, 'key' => EnvLoader::get('APP_KEY'), 'trusted_hosts' => ['school.local']],
    'cookies' => ['secure' => true, 'http_only' => true],
    'paths' => ['private_storage' => demo_storage_path('private'), 'backups' => demo_storage_path('backups'), 'logs' => demo_storage_path('logs'), 'audit' => demo_storage_path('audit')],
    'origin_protection' => [
        'enabled' => true,
        'block_direct_ip_host' => true,
        'cdn_or_proxy_enabled' => true,
        'require_cdn_or_proxy_in_production' => false,
    ],
    'security_headers' => ['hsts' => ['enabled' => true], 'csp' => ['enabled' => true], 'permissions_policy' => ['preset' => 'strict']],
    'request_validation' => ['enabled' => true, 'sanitize' => true, 'default' => ['methods' => ['POST']]],
    'authentication' => [
        'enabled' => true,
        'strategies' => ['api_bearer' => ['type' => 'bearer', 'required' => true]],
        'password_policy' => ['min_length' => 12, 'max_length' => 128],
    ],
    'authorization' => [
        'enabled' => true,
        'deny_by_default' => true,
        'policies' => ['public.read' => ['resource' => 'public_pages', 'actions' => ['read'], 'data_classes' => ['public']]],
    ],
    'request_receiving' => [
        'enabled' => true,
        'profiles' => ['api_authenticated' => ['methods' => ['GET'], 'auth' => 'bearer', 'auth_strategy' => 'api_bearer']],
    ],
    'trust_boundaries' => [
        'enabled' => true,
        'deny_unclassified_fields' => true,
        'rules' => ['public.read' => ['zones' => ['public'], 'data_classes' => ['public'], 'actions' => ['read']]],
    ],
    'uploads' => ['strict_production' => true, 'scanner' => ['driver' => 'heuristic']],
];
$report = (new ProductionSecurityChecker($config))->check();

$riskyFile = demo_storage_path('env-demo/source-with-secret.php');
file_put_contents($riskyFile, "<?php\n\$api_key = 'abcdefghijklmnopqrstuvwxyz123456';\n");
$findings = (new SecretScanner())->scanDirectory(dirname($riskyFile), []);

demo_step('Production checker report', $report);
demo_step('Secret scanner findings count', count($findings));
demo_result($report['passed'] === true && count($findings) >= 1, 'Environment loading, production checks, and secret scanning are working.');
