<?php
namespace Mnb\SecurityCore\Monitoring;

class AlertManager
{
    /** @param list<AlertRule> $rules @param list<AlertChannelInterface> $channels */
    public function __construct(private array $rules = [], private array $channels = [], private ?string $eventFile = null) {}

    /** @param array<string,mixed> $context @return list<array<string,mixed>> */
    public function recordEvent(string $event, array $context = []): array
    {
        $entry = ['time' => date('c'), 'ts' => time(), 'event' => $event, 'context' => $context];
        $this->appendEvent($entry);
        $alerts = [];
        $events = $this->events();
        foreach ($this->rules as $rule) {
            if (!$rule->matches($entry)) { continue; }
            $since = time() - $rule->windowSeconds;
            $count = 0;
            foreach ($events as $candidate) {
                if (($candidate['ts'] ?? 0) < $since) { continue; }
                if ($rule->matches($candidate)) { $count++; }
            }
            if ($count >= $rule->threshold) {
                $alert = [
                    'alert_id' => $this->newId(),
                    'time' => date('c'),
                    'rule' => $rule->name,
                    'event' => $rule->event,
                    'severity' => $rule->severity,
                    'count' => $count,
                    'window_seconds' => $rule->windowSeconds,
                    'context' => $context,
                ];
                foreach ($this->channels as $channel) { $channel->send($alert); }
                $alerts[] = $alert;
            }
        }
        return $alerts;
    }

    /** @return array<string,mixed> */
    public function summary(): array
    {
        return ['passed' => true, 'rules' => array_map(fn(AlertRule $rule): array => $rule->toArray(), $this->rules), 'events' => count($this->events())];
    }

    /** @param array<string,mixed> $entry */
    private function appendEvent(array $entry): void
    {
        if ($this->eventFile === null) { return; }
        $dir = dirname($this->eventFile);
        if (!is_dir($dir)) { mkdir($dir, 0775, true); }
        file_put_contents($this->eventFile, json_encode($entry, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . PHP_EOL, FILE_APPEND | LOCK_EX);
    }

    /** @return list<array<string,mixed>> */
    private function events(): array
    {
        if ($this->eventFile === null || !is_file($this->eventFile)) { return []; }
        $events = [];
        foreach (file($this->eventFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
            $event = json_decode($line, true);
            if (is_array($event)) { $events[] = $event; }
        }
        return $events;
    }

    private function newId(): string
    {
        try { return bin2hex(random_bytes(12)); } catch (\Throwable) { return str_replace('.', '', uniqid('alert_', true)); }
    }
}
