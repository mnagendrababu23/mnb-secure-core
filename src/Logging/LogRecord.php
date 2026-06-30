<?php
namespace Mnb\SecurityCore\Logging;

class LogRecord
{
    public const LEVEL_DEBUG = 'debug';
    public const LEVEL_INFO = 'info';
    public const LEVEL_NOTICE = 'notice';
    public const LEVEL_WARNING = 'warning';
    public const LEVEL_ERROR = 'error';
    public const LEVEL_CRITICAL = 'critical';
    public const LEVEL_ALERT = 'alert';
    public const LEVEL_EMERGENCY = 'emergency';

    /** @param array<string,mixed> $context */
    public function __construct(
        public readonly string $level,
        public readonly string $message,
        public readonly array $context = [],
        public readonly string $channel = 'app',
        public readonly ?string $time = null,
        public readonly ?string $recordId = null
    ) {
        if (!in_array($level, self::levels(), true)) {
            throw new \InvalidArgumentException('Invalid log level.');
        }
        if (!preg_match('/^[a-z][a-z0-9_.:-]{1,80}$/', $channel)) {
            throw new \InvalidArgumentException('Log channel must be a safe slug.');
        }
    }

    /** @return list<string> */
    public static function levels(): array
    {
        return [self::LEVEL_DEBUG, self::LEVEL_INFO, self::LEVEL_NOTICE, self::LEVEL_WARNING, self::LEVEL_ERROR, self::LEVEL_CRITICAL, self::LEVEL_ALERT, self::LEVEL_EMERGENCY];
    }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return [
            'record_id' => $this->recordId ?: self::newId(),
            'time' => $this->time ?: date('c'),
            'channel' => $this->channel,
            'level' => $this->level,
            'message' => $this->message,
            'context' => $this->context,
        ];
    }

    private static function newId(): string
    {
        try { return bin2hex(random_bytes(12)); } catch (\Throwable) { return str_replace('.', '', uniqid('log_', true)); }
    }
}
