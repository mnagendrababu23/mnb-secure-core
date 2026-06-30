<?php
namespace Mnb\SecurityCore\Logging;

interface LogHandlerInterface
{
    public function handle(LogRecord $record): void;
}
