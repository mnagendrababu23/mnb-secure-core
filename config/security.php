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

    'audit' => [
        'enabled' => filter_var($_ENV['AUDIT_ENABLED'] ?? true, FILTER_VALIDATE_BOOL),
        'file' => $_ENV['AUDIT_FILE'] ?? ((__DIR__ . '/../storage/audit/security-audit.log')),
        'mirror_to_log' => filter_var($_ENV['AUDIT_MIRROR_TO_LOG'] ?? false, FILTER_VALIDATE_BOOL),
        'log_file' => $_ENV['AUDIT_LOG_FILE'] ?? ((__DIR__ . '/../storage/logs/security-audit.log')),
        'auto' => [
            // Enable to automatically log safe request outcomes for add/edit/delete/submission/email/auth routes.
            'enabled' => filter_var($_ENV['AUDIT_AUTO_ENABLED'] ?? false, FILTER_VALIDATE_BOOL),
            'log_reads' => filter_var($_ENV['AUDIT_AUTO_LOG_READS'] ?? false, FILTER_VALIDATE_BOOL),
            'log_preflight' => filter_var($_ENV['AUDIT_AUTO_LOG_PREFLIGHT'] ?? false, FILTER_VALIDATE_BOOL),
            'excluded_paths' => array_values(array_filter(array_map('trim', explode(',', $_ENV['AUDIT_AUTO_EXCLUDED_PATHS'] ?? 'health,healthz,metrics,favicon.ico')))),
            'sensitive_input_keys' => ['password', 'password_confirmation', 'current_password', 'new_password', 'token', 'api_token', 'secret', 'api_key', 'authorization', 'cookie', 'session', 'csrf', 'otp', 'private_key'],
        ],
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
        // Built-in profiles: default, images, documents, videos, archives, strict.
        // Keep legacy allow-lists below for backward compatibility; set UPLOAD_PROFILE to use a preset.
        'profile' => $_ENV['UPLOAD_PROFILE'] ?? 'custom',
        'strict_production' => filter_var($_ENV['UPLOAD_STRICT_PRODUCTION'] ?? (($_ENV['APP_ENV'] ?? 'local') === 'production' ? true : false), FILTER_VALIDATE_BOOL),
        'allow_archives_in_production' => filter_var($_ENV['UPLOAD_ALLOW_ARCHIVES_IN_PRODUCTION'] ?? false, FILTER_VALIDATE_BOOL),
        'allowed_extensions' => ['jpg', 'jpeg', 'png', 'gif', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'csv'],
        'allowed_mime_prefixes' => ['image/', 'application/pdf', 'text/', 'application/vnd.', 'application/msword'],
        'blocked_extensions' => ['php', 'phtml', 'phar', 'cgi', 'pl', 'sh', 'exe', 'com', 'bat', 'cmd', 'js', 'html', 'htm', 'svg'],
        'deny_double_extensions' => true,
        'randomize_names' => true,
        'max_original_name_length' => 180,
        'reject_executable_content' => true,
        'max_archive_entries' => (int)($_ENV['UPLOAD_MAX_ARCHIVE_ENTRIES'] ?? 500),
        'max_archive_uncompressed_bytes' => (int)($_ENV['UPLOAD_MAX_ARCHIVE_UNCOMPRESSED_BYTES'] ?? 104857600),
        'profiles' => [
            'images' => ['max_bytes' => 5 * 1024 * 1024],
            'documents' => ['max_bytes' => 15 * 1024 * 1024],
            'videos' => ['max_bytes' => 100 * 1024 * 1024],
            'archives' => ['max_bytes' => 25 * 1024 * 1024],
            'strict' => ['max_bytes' => 5 * 1024 * 1024],
        ],
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
        'enabled' => filter_var($_ENV['CORS_ENABLED'] ?? true, FILTER_VALIDATE_BOOL),
        'allowed_origins' => array_values(array_filter(array_map('trim', explode(',', $_ENV['CORS_ALLOWED_ORIGINS'] ?? 'http://localhost')))),
        'allowed_origin_patterns' => array_values(array_filter(array_map('trim', explode(',', $_ENV['CORS_ALLOWED_ORIGIN_PATTERNS'] ?? '')))),
        'allowed_methods' => ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
        'allowed_headers' => ['Content-Type', 'Authorization', 'X-CSRF-Token', 'X-Requested-With'],
        'exposed_headers' => ['X-Request-ID', 'X-RateLimit-Policy', 'X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset'],
        'allow_credentials' => filter_var($_ENV['CORS_ALLOW_CREDENTIALS'] ?? false, FILTER_VALIDATE_BOOL),
        'allow_null_origin' => filter_var($_ENV['CORS_ALLOW_NULL_ORIGIN'] ?? false, FILTER_VALIDATE_BOOL),
        'allow_private_network' => filter_var($_ENV['CORS_ALLOW_PRIVATE_NETWORK'] ?? false, FILTER_VALIDATE_BOOL),
        'max_age' => (int)($_ENV['CORS_MAX_AGE'] ?? 600),
    ],
    'security_headers' => [
        'enabled' => filter_var($_ENV['SECURITY_HEADERS_ENABLED'] ?? true, FILTER_VALIDATE_BOOL),
        'hsts' => [
            'enabled' => filter_var($_ENV['HSTS_ENABLED'] ?? false, FILTER_VALIDATE_BOOL),
            'max_age' => (int)($_ENV['HSTS_MAX_AGE'] ?? 31536000),
            'include_subdomains' => filter_var($_ENV['HSTS_INCLUDE_SUBDOMAINS'] ?? true, FILTER_VALIDATE_BOOL),
            'preload' => filter_var($_ENV['HSTS_PRELOAD'] ?? false, FILTER_VALIDATE_BOOL),
            'only_on_https' => true,
        ],
        'csp' => [
            'enabled' => filter_var($_ENV['CSP_ENABLED'] ?? true, FILTER_VALIDATE_BOOL),
            'report_only' => filter_var($_ENV['CSP_REPORT_ONLY'] ?? false, FILTER_VALIDATE_BOOL),
            'nonce_enabled' => filter_var($_ENV['CSP_NONCE_ENABLED'] ?? true, FILTER_VALIDATE_BOOL),
            'auto_nonce' => filter_var($_ENV['CSP_AUTO_NONCE'] ?? false, FILTER_VALIDATE_BOOL),
            'nonce_directives' => ['script-src', 'style-src'],
            'directives' => [
                'default-src' => ["'self'"],
                'script-src' => ["'self'"],
                'style-src' => ["'self'"],
                'img-src' => ["'self'", 'data:'],
                'font-src' => ["'self'", 'data:'],
                'connect-src' => ["'self'"],
                'object-src' => ["'none'"],
                'base-uri' => ["'self'"],
                'form-action' => ["'self'"],
                'frame-ancestors' => ["'self'"],
            ],
        ],
        // Legacy frame_ancestors remains supported when custom csp.directives is not supplied.
        'frame_ancestors' => "'self'",
        'content_type_options' => 'nosniff',
        'referrer_policy' => 'strict-origin-when-cross-origin',
        'x_frame_options' => 'SAMEORIGIN',
        'permissions_policy' => [
            // strict, balanced, minimal, custom, none
            'preset' => $_ENV['PERMISSIONS_POLICY_PRESET'] ?? 'strict',
        ],
        'cross_origin_opener_policy' => $_ENV['CROSS_ORIGIN_OPENER_POLICY'] ?? 'same-origin',
        'cross_origin_resource_policy' => $_ENV['CROSS_ORIGIN_RESOURCE_POLICY'] ?? 'same-origin',
        'cross_origin_embedder_policy' => $_ENV['CROSS_ORIGIN_EMBEDDER_POLICY'] ?? null,
    ],


    'web_security' => [
        'enabled' => filter_var($_ENV['WEB_SECURITY_ENABLED'] ?? true, FILTER_VALIDATE_BOOL),
        'profiles' => [
            'browser_page' => [
                'security_headers' => true,
                'cache_policy' => 'private_user',
                'csrf' => false,
                'output_escape' => true,
            ],
            'browser_form' => [
                'security_headers' => true,
                'cache_policy' => 'sensitive_no_store',
                'csrf' => true,
                'input_validation' => true,
                'safe_redirects' => true,
                'output_escape' => true,
            ],
            'admin_panel' => [
                'security_headers' => true,
                'cache_policy' => 'sensitive_no_store',
                'csrf' => true,
                'auth_strategy' => 'admin_bearer',
                'authorization' => true,
                'frame_policy' => 'deny',
            ],
            'json_api' => [
                'security_headers' => true,
                'cors' => true,
                'cache_policy' => 'no_store',
                'input_validation' => true,
                'auth_strategy' => 'api_bearer',
                'authorization' => true,
            ],
            'upload_endpoint' => [
                'security_headers' => true,
                'cache_policy' => 'no_store',
                'csrf' => false,
                'auth_strategy' => 'api_bearer',
                'upload_profile' => 'documents',
            ],
        ],
        'redirects' => [
            'allow_external' => filter_var($_ENV['WEB_REDIRECT_ALLOW_EXTERNAL'] ?? false, FILTER_VALIDATE_BOOL),
            'allowed_hosts' => array_values(array_filter(array_map('trim', explode(',', $_ENV['WEB_REDIRECT_ALLOWED_HOSTS'] ?? '')))),
        ],
        'cookies' => [
            'secure' => filter_var($_ENV['WEB_COOKIE_SECURE'] ?? (($_ENV['APP_ENV'] ?? 'local') === 'production'), FILTER_VALIDATE_BOOL),
            'http_only' => filter_var($_ENV['WEB_COOKIE_HTTP_ONLY'] ?? true, FILTER_VALIDATE_BOOL),
            'same_site' => $_ENV['WEB_COOKIE_SAME_SITE'] ?? 'Lax',
            'path' => '/',
        ],
        'cache' => [
            'profiles' => [],
        ],
        'html_sanitizer' => [
            'allowed_tags' => ['p', 'br', 'strong', 'em', 'ul', 'ol', 'li', 'a'],
            'allowed_attributes' => ['href', 'title'],
            'allow_data_images' => false,
        ],
        'signed_urls' => [
            'key' => $_ENV['SIGNED_URL_KEY'] ?? ($_ENV['APP_KEY'] ?? ''),
            'default_ttl' => (int)($_ENV['SIGNED_URL_TTL'] ?? 900),
        ],
    ],

    'request_validation' => [
        'enabled' => filter_var($_ENV['REQUEST_VALIDATION_ENABLED'] ?? true, FILTER_VALIDATE_BOOL),
        'sanitize' => filter_var($_ENV['REQUEST_SANITIZE_ENABLED'] ?? true, FILTER_VALIDATE_BOOL),
        'throw' => false,
        'error_status' => 422,
        'message' => 'Validation failed',
        'max_depth' => (int)($_ENV['REQUEST_VALIDATION_MAX_DEPTH'] ?? 10),
        'max_string_length' => (int)($_ENV['REQUEST_VALIDATION_MAX_STRING_LENGTH'] ?? 10000),
        'blocked_keys' => ['__proto__', 'prototype', 'constructor'],
        'default' => [
            'methods' => ['POST', 'PUT', 'PATCH'],
            'body' => [
                'sanitize' => true,
                'sanitize_rules' => ['*' => 'trim|strip_control_chars'],
            ],
            'query' => [
                'sanitize' => true,
                'sanitize_rules' => ['*' => 'trim|strip_control_chars'],
            ],
        ],
        // Define route-specific validation in applications:
        // 'routes' => [
        //     'register' => [
        //         'methods' => ['POST'],
        //         'path' => '/register',
        //         'body' => [
        //             'allowed_fields' => ['name', 'email', 'password'],
        //             'strict' => true,
        //             'sanitize_rules' => ['name' => 'trim|strip_tags|collapse_spaces|max_length:120', 'email' => 'trim|email'],
        //             'rules' => ['name' => 'required|string|min:2|max:120', 'email' => 'required|email|max:190', 'password' => 'required|string|min:8|max:128'],
        //         ],
        //     ],
        // ],
        'routes' => [],
    ],


    'authentication' => [
        'enabled' => filter_var($_ENV['AUTHENTICATION_ENABLED'] ?? true, FILTER_VALIDATE_BOOL),
        'defaults' => [
            'failure_message' => 'Authentication required',
            'audit' => true,
            'required' => true,
        ],
        'strategies' => [
            'api_bearer' => [
                'type' => 'bearer',
                'required' => true,
                'rate_policy' => 'api',
                'audit' => true,
            ],
            'optional_bearer' => [
                'type' => 'bearer',
                'required' => false,
                'audit' => false,
            ],
            'admin_bearer' => [
                'type' => 'bearer',
                'required' => true,
                'roles' => ['admin', 'super_admin'],
                'rate_policy' => 'api',
                'audit' => true,
            ],
            'web_session' => [
                'type' => 'session',
                'required' => true,
                'roles' => [],
                'audit' => true,
            ],
            'webhook_hmac' => [
                'type' => 'signature',
                'required' => true,
                'scopes' => ['webhook:receive'],
                'signature' => [
                    'signature_header' => $_ENV['WEBHOOK_SIGNATURE_HEADER'] ?? 'X-Signature',
                    'timestamp_header' => $_ENV['WEBHOOK_TIMESTAMP_HEADER'] ?? 'X-Timestamp',
                    'algorithm' => $_ENV['WEBHOOK_SIGNATURE_ALGORITHM'] ?? 'sha256',
                    'secret' => $_ENV['WEBHOOK_SECRET'] ?? '',
                    'tolerance_seconds' => (int)($_ENV['WEBHOOK_TIMESTAMP_TOLERANCE'] ?? 300),
                ],
                'audit' => true,
            ],
            'internal_system' => [
                'type' => 'bearer',
                'required' => true,
                'scopes' => ['system:*'],
                'roles' => ['system', 'internal_system'],
                'audit' => true,
            ],
        ],
        'password_policy' => [
            'min_length' => (int)($_ENV['PASSWORD_MIN_LENGTH'] ?? 12),
            'max_length' => (int)($_ENV['PASSWORD_MAX_LENGTH'] ?? 128),
            'require_mixed_case' => filter_var($_ENV['PASSWORD_REQUIRE_MIXED_CASE'] ?? false, FILTER_VALIDATE_BOOL),
            'require_number' => filter_var($_ENV['PASSWORD_REQUIRE_NUMBER'] ?? false, FILTER_VALIDATE_BOOL),
            'require_symbol' => filter_var($_ENV['PASSWORD_REQUIRE_SYMBOL'] ?? false, FILTER_VALIDATE_BOOL),
            'block_common_passwords' => filter_var($_ENV['PASSWORD_BLOCK_COMMON'] ?? true, FILTER_VALIDATE_BOOL),
            'block_user_context' => filter_var($_ENV['PASSWORD_BLOCK_USER_CONTEXT'] ?? true, FILTER_VALIDATE_BOOL),
        ],
        'login' => [
            'rate_policy' => 'login',
            'generic_failure_message' => 'Invalid credentials',
            'audit_failures' => true,
            'ttl_seconds' => (int)($_ENV['AUTH_TOKEN_TTL_SECONDS'] ?? 2592000),
        ],
    ],


    'authorization' => [
        'enabled' => filter_var($_ENV['AUTHORIZATION_ENABLED'] ?? true, FILTER_VALIDATE_BOOL),
        'deny_by_default' => filter_var($_ENV['AUTHORIZATION_DENY_BY_DEFAULT'] ?? true, FILTER_VALIDATE_BOOL),
        'audit_denials' => filter_var($_ENV['AUTHORIZATION_AUDIT_DENIALS'] ?? true, FILTER_VALIDATE_BOOL),
        'hide_denial_reasons' => filter_var($_ENV['AUTHORIZATION_HIDE_DENIAL_REASONS'] ?? true, FILTER_VALIDATE_BOOL),
        'policies' => [
            'public.read' => [
                'resource' => 'public_pages',
                'actions' => ['read'],
                'data_classes' => ['public'],
                'audit' => false,
                'fields' => [
                    'read' => ['*' => ['title', 'slug', 'body']],
                ],
            ],
            'students.read' => [
                'resource' => 'students',
                'actions' => ['read'],
                'roles' => ['school_admin', 'super_admin'],
                'permissions' => ['student.view'],
                'scopes' => ['students:read', 'student.view'],
                'tenant_required' => true,
                'data_classes' => ['internal', 'confidential', 'sensitive'],
                'trust_boundary' => 'students.read',
                'audit' => true,
                'fields' => [
                    'read' => [
                        'school_admin' => ['id', 'name', 'email', 'parent_phone', 'school_id', 'branch_id'],
                        'super_admin' => ['*'],
                    ],
                ],
            ],
            'students.update' => [
                'resource' => 'students',
                'actions' => ['update'],
                'roles' => ['school_admin', 'super_admin'],
                'permissions' => ['student.update'],
                'scopes' => ['students:update', 'student.update'],
                'tenant_required' => true,
                'data_classes' => ['sensitive'],
                'trust_boundary' => 'students.update',
                'audit' => true,
                'fields' => [
                    'write' => [
                        'school_admin' => ['name', 'email', 'parent_phone', 'branch_id'],
                        'super_admin' => ['*'],
                    ],
                ],
            ],
            'students.delete' => [
                'resource' => 'students',
                'actions' => ['delete'],
                'roles' => ['super_admin'],
                'permissions' => ['student.delete'],
                'scopes' => ['students:delete', 'student.delete'],
                'tenant_required' => true,
                'data_classes' => ['sensitive'],
                'trust_boundary' => 'students.delete',
                'audit' => true,
            ],
            'backup.run' => [
                'resource' => 'backups',
                'actions' => ['backup'],
                'roles' => ['internal_system', 'system'],
                'scopes' => ['system:backup', 'system:*'],
                'data_classes' => ['highly_sensitive'],
                'trust_boundary' => 'backup.run',
                'audit' => true,
            ],
        ],
    ],


    'data_protection' => [
        'enabled' => filter_var($_ENV['DATA_PROTECTION_ENABLED'] ?? true, FILTER_VALIDATE_BOOL),
        'default_class' => $_ENV['DATA_PROTECTION_DEFAULT_CLASS'] ?? 'internal',
        'deny_unclassified_fields' => filter_var($_ENV['DATA_PROTECTION_DENY_UNCLASSIFIED_FIELDS'] ?? false, FILTER_VALIDATE_BOOL),
        'audit' => filter_var($_ENV['DATA_PROTECTION_AUDIT'] ?? false, FILTER_VALIDATE_BOOL),
        'encryption' => [
            'enabled' => filter_var($_ENV['DATA_ENCRYPTION_ENABLED'] ?? true, FILTER_VALIDATE_BOOL),
            'current_key_id' => $_ENV['DATA_KEY_ID'] ?? 'app-v1',
            'keys' => [
                $_ENV['DATA_KEY_ID'] ?? 'app-v1' => $_ENV['DATA_KEY'] ?? ($_ENV['APP_KEY'] ?? ''),
            ],
            'aad' => filter_var($_ENV['DATA_ENCRYPTION_AAD'] ?? true, FILTER_VALIDATE_BOOL),
        ],
        'search_hash' => [
            'enabled' => filter_var($_ENV['DATA_SEARCH_HASH_ENABLED'] ?? true, FILTER_VALIDATE_BOOL),
            'key' => $_ENV['DATA_SEARCH_HASH_KEY'] ?? ($_ENV['APP_KEY'] ?? ''),
            'prefix' => $_ENV['DATA_SEARCH_HASH_PREFIX'] ?? 'mnb:search',
        ],
        'resources' => [
            'students' => [
                'default_class' => 'sensitive',
                'tenant_scoped' => true,
                'fields' => [
                    'id' => ['class' => 'internal'],
                    'name' => ['class' => 'internal'],
                    'email' => ['class' => 'confidential', 'encrypt' => true, 'search_hash' => true, 'mask' => 'email', 'export' => 'masked', 'log' => false],
                    'parent_phone' => ['class' => 'sensitive', 'encrypt' => true, 'search_hash' => true, 'mask' => 'last4', 'export' => 'masked', 'log' => false],
                    'school_id' => ['class' => 'internal'],
                    'branch_id' => ['class' => 'internal'],
                    'password_hash' => ['class' => 'highly_sensitive', 'read' => false, 'write' => false, 'export' => false, 'log' => false],
                ],
            ],
        ],
        'exports' => [
            'csv_injection_protection' => true,
            'audit' => true,
            'max_rows' => (int)($_ENV['DATA_EXPORT_MAX_ROWS'] ?? 50000),
        ],
        'storage' => [
            'encrypt_files' => filter_var($_ENV['DATA_ENCRYPT_FILES'] ?? false, FILTER_VALIDATE_BOOL),
        ],
        'backups' => [
            'encrypt' => filter_var($_ENV['DATA_BACKUP_ENCRYPT'] ?? false, FILTER_VALIDATE_BOOL),
            'sign' => filter_var($_ENV['DATA_BACKUP_SIGN'] ?? false, FILTER_VALIDATE_BOOL),
            'retention_days' => (int)($_ENV['DATA_BACKUP_RETENTION_DAYS'] ?? 30),
        ],
        'logs' => [
            'redact_before_write' => true,
        ],
    ],


    'request_receiving' => [
        'enabled' => filter_var($_ENV['REQUEST_RECEIVING_ENABLED'] ?? true, FILTER_VALIDATE_BOOL),
        'reject_body_on_get' => true,
        'blocked_methods' => ['TRACE', 'CONNECT'],
        'json_depth' => (int)($_ENV['REQUEST_JSON_DEPTH'] ?? 64),
        'json_max_bytes' => (int)($_ENV['REQUEST_JSON_MAX_BYTES'] ?? 1048576),
        'json_require_object' => true,
        'request_id' => [
            'header' => $_ENV['REQUEST_ID_HEADER'] ?? 'X-Request-ID',
            'accept_incoming' => filter_var($_ENV['REQUEST_ID_ACCEPT_INCOMING'] ?? true, FILTER_VALIDATE_BOOL),
            'max_length' => (int)($_ENV['REQUEST_ID_MAX_LENGTH'] ?? 80),
        ],
        'suspicious' => [
            // block or audit
            'mode' => $_ENV['SUSPICIOUS_REQUEST_MODE'] ?? 'block',
            'max_path_length' => (int)($_ENV['REQUEST_MAX_PATH_LENGTH'] ?? 2048),
            'max_parameters' => (int)($_ENV['REQUEST_MAX_PARAMETERS'] ?? 200),
        ],
        'webhook' => [
            'signature_header' => $_ENV['WEBHOOK_SIGNATURE_HEADER'] ?? 'X-Signature',
            'timestamp_header' => $_ENV['WEBHOOK_TIMESTAMP_HEADER'] ?? 'X-Timestamp',
            'algorithm' => $_ENV['WEBHOOK_SIGNATURE_ALGORITHM'] ?? 'sha256',
            'secret' => $_ENV['WEBHOOK_SECRET'] ?? '',
            'tolerance_seconds' => (int)($_ENV['WEBHOOK_TIMESTAMP_TOLERANCE'] ?? 300),
        ],
        'defaults' => [
            'request_id' => true,
            'request_trust' => true,
            'origin_protection' => true,
            'https' => true,
            'trusted_host' => true,
            'cors' => true,
            'security_headers' => true,
            'json_body' => true,
            'suspicious_detection' => true,
            'input_validation' => true,
            'auto_audit' => true,
        ],
        'profiles' => [
            'public_read' => [
                'methods' => ['GET', 'HEAD'],
                'max_bytes' => 65536,
                'content_types' => [],
                'rate_policy' => 'api',
                'auth' => null,
                'csrf' => false,
                'input_validation' => false,
                'auto_audit' => false,
            ],
            'public_form' => [
                'methods' => ['POST'],
                'max_bytes' => 1048576,
                'content_types' => ['application/x-www-form-urlencoded', 'multipart/form-data'],
                'rate_policy' => 'api',
                'auth' => null,
                'csrf' => true,
                'input_validation' => true,
                'auto_audit' => true,
            ],
            'api_public' => [
                'methods' => ['GET', 'POST'],
                'max_bytes' => 1048576,
                'content_types' => ['application/json'],
                'rate_policy' => 'api',
                'auth' => null,
                'csrf' => false,
                'input_validation' => true,
            ],
            'api_authenticated' => [
                'methods' => ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
                'max_bytes' => 1048576,
                'content_types' => ['application/json'],
                'rate_policy' => 'api',
                'auth' => 'bearer',
                'csrf' => false,
                'input_validation' => true,
                'trust_boundary' => null,
                'authorization' => null,
            ],
            'admin' => [
                'methods' => ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
                'max_bytes' => 1048576,
                'content_types' => ['application/json', 'application/x-www-form-urlencoded'],
                'rate_policy' => 'api',
                'auth' => 'bearer',
                'required_roles' => ['admin', 'super_admin'],
                'authorization' => 'students.read',
                'input_validation' => true,
                'auto_audit' => true,
            ],
            'upload_image' => [
                'methods' => ['POST'],
                'max_bytes' => 5242880,
                'content_types' => ['multipart/form-data'],
                'rate_policy' => 'api',
                'auth' => 'bearer',
                'upload_profile' => 'images',
                'input_validation' => true,
                'auto_audit' => true,
            ],
            'webhook' => [
                'methods' => ['POST'],
                'max_bytes' => 1048576,
                'content_types' => ['application/json'],
                'rate_policy' => 'api',
                'auth' => 'signature',
                'csrf' => false,
                'input_validation' => true,
                'auto_audit' => true,
            ],
            'internal_system' => [
                'methods' => ['POST'],
                'max_bytes' => 1048576,
                'content_types' => ['application/json'],
                'rate_policy' => 'api',
                'auth' => 'bearer',
                'trust_boundary' => 'backup.run',
                'input_validation' => true,
                'auto_audit' => true,
            ],
        ],
    ],


    'trust_boundaries' => [
        'enabled' => filter_var($_ENV['TRUST_BOUNDARIES_ENABLED'] ?? true, FILTER_VALIDATE_BOOL),
        'hide_denial_reasons' => filter_var($_ENV['TRUST_BOUNDARY_HIDE_DENIAL_REASONS'] ?? true, FILTER_VALIDATE_BOOL),
        'deny_unclassified_fields' => filter_var($_ENV['TRUST_BOUNDARY_DENY_UNCLASSIFIED_FIELDS'] ?? false, FILTER_VALIDATE_BOOL),
        'zones' => ['public', 'authenticated', 'school_admin', 'super_admin', 'internal_system'],
        'zone_data_access' => [
            'public' => ['public'],
            'authenticated' => ['public', 'internal'],
            'school_admin' => ['public', 'internal', 'confidential', 'sensitive'],
            'super_admin' => ['public', 'internal', 'confidential', 'sensitive'],
            'internal_system' => ['public', 'internal', 'confidential', 'sensitive', 'highly_sensitive'],
        ],
        'zone_resolvers' => [
            'school_admin' => ['roles' => ['school_admin', 'admin'], 'scopes' => ['school:*'], 'permissions' => ['school.manage', 'student.manage']],
            'super_admin' => ['roles' => ['super_admin', 'root', 'owner'], 'scopes' => ['admin:*', '*']],
            'internal_system' => ['roles' => ['internal_system', 'system'], 'scopes' => ['system:*', 'internal:*']],
        ],
        'resources' => [
            'students' => [
                'data_class' => 'sensitive',
                'tenant_scoped' => true,
                'fields' => [
                    'id' => 'internal',
                    'name' => 'internal',
                    'email' => 'confidential',
                    'parent_phone' => 'sensitive',
                    'school_id' => 'internal',
                    'branch_id' => 'internal',
                    'password_hash' => 'highly_sensitive',
                ],
            ],
            'public_pages' => [
                'data_class' => 'public',
                'tenant_scoped' => false,
                'fields' => ['title' => 'public', 'slug' => 'public', 'body' => 'public'],
            ],
        ],
        'rules' => [
            'public.read' => [
                'zones' => ['public', 'authenticated', 'school_admin', 'super_admin'],
                'data_classes' => ['public'],
                'actions' => ['read'],
                'resources' => ['public_pages'],
                'audit' => false,
            ],
            'students.read' => [
                'zones' => ['school_admin', 'super_admin'],
                'data_classes' => ['internal', 'confidential', 'sensitive'],
                'actions' => ['read'],
                'resources' => ['students'],
                'permissions' => ['student.view'],
                'tenant_required' => true,
                'audit' => true,
            ],
            'students.update' => [
                'zones' => ['school_admin', 'super_admin'],
                'data_classes' => ['sensitive'],
                'actions' => ['update'],
                'resources' => ['students'],
                'permissions' => ['student.update'],
                'tenant_required' => true,
                'audit' => true,
            ],
            'students.delete' => [
                'zones' => ['super_admin'],
                'data_classes' => ['sensitive'],
                'actions' => ['delete'],
                'resources' => ['students'],
                'permissions' => ['student.delete'],
                'tenant_required' => true,
                'audit' => true,
            ],
            'backup.run' => [
                'zones' => ['internal_system'],
                'data_classes' => ['highly_sensitive'],
                'actions' => ['backup'],
                'scopes' => ['system:backup', 'system:*'],
                'audit' => true,
            ],
        ],
    ],

    'suggestions' => [
        'enabled' => filter_var($_ENV['SUGGESTIONS_ENABLED'] ?? true, FILTER_VALIDATE_BOOL),
        'max_results' => (int)($_ENV['SUGGESTIONS_MAX_RESULTS'] ?? 8),
        'rules' => [],
    ],

    'origin_protection' => [
        // This helps hide server/application identity. To truly hide the origin IP,
        // also use a CDN/reverse proxy and firewall the origin server.
        'enabled' => filter_var($_ENV['ORIGIN_PROTECTION_ENABLED'] ?? true, FILTER_VALIDATE_BOOL),
        'block_direct_ip_host' => filter_var($_ENV['BLOCK_DIRECT_IP_HOST'] ?? true, FILTER_VALIDATE_BOOL),
        'cdn_or_proxy_enabled' => filter_var($_ENV['CDN_OR_PROXY_ENABLED'] ?? false, FILTER_VALIDATE_BOOL),
        'require_cdn_or_proxy_in_production' => filter_var($_ENV['REQUIRE_CDN_OR_PROXY_IN_PRODUCTION'] ?? true, FILTER_VALIDATE_BOOL),
        // Reject spoofed Forwarded/X-Forwarded-* headers unless REMOTE_ADDR is trusted.
        'block_untrusted_forwarded_headers' => filter_var($_ENV['BLOCK_UNTRUSTED_FORWARDED_HEADERS'] ?? true, FILTER_VALIDATE_BOOL),
        // Enable only when every valid request reaches PHP through a configured trusted proxy/CDN.
        'require_trusted_proxy' => filter_var($_ENV['REQUIRE_TRUSTED_PROXY'] ?? false, FILTER_VALIDATE_BOOL),
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
