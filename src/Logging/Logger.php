<?php
namespace Mnb\SecurityCore\Logging;

use Mnb\SecurityCore\Contracts\LoggerInterface;

class Logger implements LoggerInterface
{
    /** @param list<LogHandlerInterface> $handlers */
    public function __construct(private array $handlers = [], private string $channel = 'app', private string $minLevel = LogRecord::LEVEL_INFO) {}

    /** @param array<string,mixed> $context */
    public function debug(string $message, array $context = []): void { $this->log(LogRecord::LEVEL_DEBUG, $message, $context); }
    /** @param array<string,mixed> $context */
    public function info(string $message, array $context = []): void { $this->log(LogRecord::LEVEL_INFO, $message, $context); }
    /** @param array<string,mixed> $context */
    public function notice(string $message, array $context = []): void { $this->log(LogRecord::LEVEL_NOTICE, $message, $context); }
    /** @param array<string,mixed> $context */
    public function warning(string $message, array $context = []): void { $this->log(LogRecord::LEVEL_WARNING, $message, $context); }
    /** @param array<string,mixed> $context */
    public function error(string $message, array $context = []): void { $this->log(LogRecord::LEVEL_ERROR, $message, $context); }
    /** @param array<string,mixed> $context */
    public function critical(string $message, array $context = []): void { $this->log(LogRecord::LEVEL_CRITICAL, $message, $context); }
    /** @param array<string,mixed> $context */
    public function alert(string $message, array $context = []): void { $this->log(LogRecord::LEVEL_ALERT, $message, $context); }

    /** @param array<string,mixed> $context */
    public function log(string $level, string $message, array $context = []): void
    {
        if (!$this->isAllowed($level)) {
            return;
        }
        $record = new LogRecord($level, $message, $context, $this->channel);
        foreach ($this->handlers as $handler) {
            $handler->handle($record);
        }
    }

    private function isAllowed(string $level): bool
    {
        $rank = [
            LogRecord::LEVEL_DEBUG => 10,
            LogRecord::LEVEL_INFO => 20,
            LogRecord::LEVEL_NOTICE => 25,
            LogRecord::LEVEL_WARNING => 30,
            LogRecord::LEVEL_ERROR => 40,
            LogRecord::LEVEL_CRITICAL => 50,
            LogRecord::LEVEL_ALERT => 60,
            LogRecord::LEVEL_EMERGENCY => 70,
        ];
        return ($rank[$level] ?? 999) >= ($rank[$this->minLevel] ?? 20);
    }
}
