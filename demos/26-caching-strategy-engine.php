<?php
require __DIR__ . '/_demo_bootstrap.php';

use Mnb\SecurityCore\Core\SecurityKernel;

demo_title('26. Caching Strategy Engine');

$config = require __DIR__ . '/../config/security.php';
$config = array_replace_recursive($config, [
    'app' => ['key' => str_repeat('C', 40), 'env' => 'testing'],
    'paths' => ['cache' => demo_storage_path('cache-strategy/cache')],
    'data_protection' => [
        'encryption' => [
            'current_key_id' => 'cache-demo',
            'keys' => ['cache-demo' => str_repeat('D', 40)],
        ],
    ],
]);
unset($config['data_protection']['encryption']['keys']['app-v1']);

$kernel = new SecurityKernel($config);
$cache = $kernel->secureCache();

$context = ['school_id' => 10, 'user_id' => 15, 'resource_id' => 44];
$decision = $cache->put('student_profile', $context, [
    'name' => 'Ravi',
    'parent_phone' => '9876543210',
]);

$profile = $cache->remember('student_profile', $context, fn () => ['name' => 'Fallback']);

$invalidator = $kernel->cacheInvalidator();
$flushed = $invalidator->invalidateTags(['students', 'school:10']);
$afterFlush = $cache->get('student_profile', $context);

$guard = $kernel->cacheStampedeGuard();
$counter = 0;
$valueA = $guard->rememberLocked('demo-expensive-' . getmypid(), 60, function () use (&$counter): array {
    $counter++;
    return ['count' => $counter];
});
$valueB = $guard->rememberLocked('demo-expensive-' . getmypid(), 60, function () use (&$counter): array {
    $counter++;
    return ['count' => $counter];
});

demo_step('Cache policy', $decision->policy());
demo_step('Decision encrypted', $decision->encrypted());
demo_step('Profile from cache', $profile);
demo_step('Invalidated keys', $flushed);
demo_step('Value after tag invalidation', $afterFlush);
demo_step('Stampede guard values', [$valueA, $valueB]);

demo_result($decision->allowed() && $decision->encrypted(), 'Sensitive cache policy was allowed and encrypted.');
demo_result($profile['parent_phone'] === '9876543210', 'Secure cache retrieved the protected tenant/user scoped payload.');
demo_result($afterFlush === null, 'Cache invalidator flushed tagged student data.');
demo_result($counter === 1 && $valueA === $valueB, 'Stampede guard reused computed value without rebuilding.');
