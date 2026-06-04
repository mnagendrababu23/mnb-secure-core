<?php
require_once __DIR__ . '/_demo_bootstrap.php';

use Mnb\SecurityCore\Cache\FileCache;

demo_title('09. Caching Strategy');

$cache = new FileCache(demo_storage_path('cache'));
$cache->put('school:10:settings', ['school_name' => 'BOSS Demo School', 'academic_year' => '2026-2027'], 300);
$settings = $cache->get('school:10:settings');
$cache->forget('school:10:settings');
$afterClear = $cache->get('school:10:settings', 'missing');

demo_step('Cached settings', $settings);
demo_step('After invalidation', $afterClear);
demo_result(($settings['school_name'] ?? '') === 'BOSS Demo School' && $afterClear === 'missing', 'Cache put/get and invalidation are working.');
