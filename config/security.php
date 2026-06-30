<?php
return [
    'app' => [
        'env' => $_ENV['APP_ENV'] ?? 'local',
        'debug' => filter_var($_ENV['APP_DEBUG'] ?? false, FILTER_VALIDATE_BOOL),
        'url' => $_ENV['APP_URL'] ?? 'http://localhost',
        'key' => $_ENV['APP_KEY'] ?? '',
        'force_https' => filter_var($_ENV['FORCE_HTTPS'] ?? false, FILTER_VALIDATE_BOOL),
        'trusted_hosts' => array_filter(array_map('trim', explode(',', $_ENV['TRUSTED_HOSTS'] ?? 'localhost'))),
        // X-Forwarded-* headers are trusted only when REMOTE_ADDR is in this list.
        'trusted_proxies' => array_filter(array_map('trim', explode(',', $_ENV['TRUSTED_PROXIES'] ?? ''))),
    ],
    'cookies' => [
        'secure' => filter_var($_ENV['SESSION_SECURE'] ?? false, FILTER_VALIDATE_BOOL),
        'http_only' => filter_var($_ENV['SESSION_HTTP_ONLY'] ?? true, FILTER_VALIDATE_BOOL),
        'same_site' => $_ENV['SESSION_SAME_SITE'] ?? 'Lax',
    ],
    'paths' => [
        'private_storage' => $_ENV['STORAGE_PRIVATE_PATH'] ?? __DIR__ . '/../storage/private',
        'quarantine' => $_ENV['STORAGE_QUARANTINE_PATH'] ?? __DIR__ . '/../storage/quarantine',
        'cache' => $_ENV['CACHE_PATH'] ?? __DIR__ . '/../storage/cache',
        'logs' => $_ENV['LOG_PATH'] ?? __DIR__ . '/../storage/logs',
        'audit' => $_ENV['AUDIT_PATH'] ?? __DIR__ . '/../storage/audit',
        'backups' => $_ENV['BACKUP_PATH'] ?? __DIR__ . '/../storage/backups',
        'tokens' => $_ENV['TOKEN_STORE_FILE'] ?? __DIR__ . '/../storage/tokens/tokens.json',
    ],
    'limits' => [
        'request_max_bytes' => 5 * 1024 * 1024,
        'upload_max_bytes' => 10 * 1024 * 1024,
        'login' => ['max' => 5, 'seconds' => 600, 'key_by' => ['ip', 'route']],
        'api' => ['max' => 120, 'seconds' => 60, 'key_by' => ['ip', 'user', 'route']],
        'otp' => ['max' => 3, 'seconds' => 600, 'key_by' => ['ip', 'user', 'route']],
        'export' => ['max' => 10, 'seconds' => 3600, 'key_by' => ['user', 'route']],
    ],
    'uploads' => [
        'allowed_extensions' => ['jpg', 'jpeg', 'png', 'gif', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'csv'],
        'allowed_mime_prefixes' => ['image/', 'application/pdf', 'text/', 'application/vnd.', 'application/msword'],
        'blocked_extensions' => ['php', 'phtml', 'phar', 'cgi', 'pl', 'sh', 'exe', 'com', 'bat', 'cmd', 'js', 'html', 'htm', 'svg'],
        'deny_double_extensions' => true,
        'randomize_names' => true,
        'max_original_name_length' => 180,
        'reject_executable_content' => true,
        'scanner' => [
            // none, heuristic, clamav, composite
            'driver' => $_ENV['UPLOAD_SCANNER_DRIVER'] ?? 'heuristic',
            'clamav_binary' => $_ENV['CLAMAV_BINARY'] ?? 'clamscan',
            'timeout_seconds' => (int)($_ENV['UPLOAD_SCAN_TIMEOUT'] ?? 30),
            'fail_closed' => filter_var($_ENV['UPLOAD_SCAN_FAIL_CLOSED'] ?? (($_ENV['APP_ENV'] ?? 'local') === 'production' ? true : false), FILTER_VALIDATE_BOOL),
            'heuristic_read_bytes' => (int)($_ENV['UPLOAD_HEURISTIC_READ_BYTES'] ?? 2097152),
        ],
    ],

    'cache' => [
        // file, redis, database
        'driver' => $_ENV['CACHE_DRIVER'] ?? 'file',
        'prefix' => $_ENV['CACHE_PREFIX'] ?? 'mnb:cache:',
        'table' => $_ENV['CACHE_TABLE'] ?? 'mnb_cache',
    ],
    'rate_limiter' => [
        // file, redis, database
        'driver' => $_ENV['RATE_LIMIT_DRIVER'] ?? 'file',
        'prefix' => $_ENV['RATE_LIMIT_PREFIX'] ?? 'mnb:rate:',
        'table' => $_ENV['RATE_LIMIT_TABLE'] ?? 'mnb_rate_limits',
    ],
    'token_store' => [
        // file, redis, database
        'driver' => $_ENV['TOKEN_STORE_DRIVER'] ?? 'file',
        'prefix' => $_ENV['TOKEN_STORE_PREFIX'] ?? 'mnb:token:',
        'table' => $_ENV['TOKEN_STORE_TABLE'] ?? 'mnb_api_tokens',
    ],
    'redis' => [
        'host' => $_ENV['REDIS_HOST'] ?? '127.0.0.1',
        'port' => (int)($_ENV['REDIS_PORT'] ?? 6379),
        'password' => $_ENV['REDIS_PASSWORD'] ?? null,
        'database' => isset($_ENV['REDIS_DATABASE']) ? (int)$_ENV['REDIS_DATABASE'] : null,
        'timeout' => (float)($_ENV['REDIS_TIMEOUT'] ?? 1.5),
    ],

    'cors' => [
        'allowed_origins' => ['http://localhost'],
        'allowed_methods' => ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
        'allowed_headers' => ['Content-Type', 'Authorization', 'X-CSRF-Token'],
    ],
    'security_headers' => [
        'hsts' => false,
        'frame_ancestors' => "'self'",
        'content_type_options' => 'nosniff',
        'referrer_policy' => 'strict-origin-when-cross-origin',
    ],

    'origin_protection' => [
        // This helps hide server/application identity. To truly hide the origin IP,
        // also use a CDN/reverse proxy and firewall the origin server.
        'enabled' => filter_var($_ENV['ORIGIN_PROTECTION_ENABLED'] ?? true, FILTER_VALIDATE_BOOL),
        'block_direct_ip_host' => filter_var($_ENV['BLOCK_DIRECT_IP_HOST'] ?? true, FILTER_VALIDATE_BOOL),
        'cdn_or_proxy_enabled' => filter_var($_ENV['CDN_OR_PROXY_ENABLED'] ?? false, FILTER_VALIDATE_BOOL),
        'require_cdn_or_proxy_in_production' => filter_var($_ENV['REQUIRE_CDN_OR_PROXY_IN_PRODUCTION'] ?? true, FILTER_VALIDATE_BOOL),
        'strip_headers' => ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version', 'X-Generator', 'X-Runtime', 'X-Version'],
    ],


    'errors' => [
        'hide_frontend_errors' => true,
        'response_format' => 'auto', // auto, json, html, text
        'default_public_message' => 'Something went wrong. Please try again later.',
        'include_request_id' => true,
        'log_channel' => 'errors',
    ],


    'memory' => [
        'max_bytes' => 0, // 0 means use PHP memory_limit / unlimited when PHP is unlimited
        'warning_ratio' => (float)(getenv('MEMORY_WARNING_RATIO') ?: 0.75),
        'critical_ratio' => (float)(getenv('MEMORY_CRITICAL_RATIO') ?: 0.90),
        'default_chunk_size' => (int)(getenv('MEMORY_DEFAULT_CHUNK_SIZE') ?: 500),
        'min_chunk_size' => 25,
        'max_chunk_size' => (int)(getenv('MEMORY_MAX_CHUNK_SIZE') ?: 5000),
        'log_snapshots' => false,
        'guard_requests' => true,
    ],
    'database' => [
        'driver' => getenv('DB_DRIVER') ?: 'mysql',
        'host' => getenv('DB_HOST') ?: '127.0.0.1',
        'port' => getenv('DB_PORT') ?: '3306',
        'database' => getenv('DB_DATABASE') ?: '',
        'username' => getenv('DB_USERNAME') ?: '',
        'password' => getenv('DB_PASSWORD') ?: '',
        'charset' => getenv('DB_CHARSET') ?: 'utf8mb4',
        'require_policies' => true,
        'soft_delete_default' => true,
    ],


    'throughput' => [
        'target_rps' => (float)(getenv('THROUGHPUT_TARGET_RPS') ?: 50),
        'warning_latency_ms' => (int)(getenv('THROUGHPUT_WARNING_LATENCY_MS') ?: 750),
        'critical_latency_ms' => (int)(getenv('THROUGHPUT_CRITICAL_LATENCY_MS') ?: 2000),
        'max_concurrency' => (int)(getenv('THROUGHPUT_MAX_CONCURRENCY') ?: 25),
        'queue_warning_depth' => (int)(getenv('THROUGHPUT_QUEUE_WARNING_DEPTH') ?: 1000),
        'sample_window_seconds' => (int)(getenv('THROUGHPUT_SAMPLE_WINDOW_SECONDS') ?: 60),
        'emit_headers' => true,
        'block_critical_latency' => false,
    ],

    'pentest' => [
        'report_storage' => getenv('PENTEST_REPORT_PATH') ?: __DIR__ . '/../storage/logs',
        'block_release_on_open_critical' => true,
        'block_release_on_open_high' => true,
        'default_scope' => ['web', 'api', 'database', 'files'],
    ],
];
