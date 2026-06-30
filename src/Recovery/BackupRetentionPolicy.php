<?php
namespace Mnb\SecurityCore\Recovery;

class BackupRetentionPolicy
{
    public function __construct(private int $dailyDays = 7, private int $weeklyWeeks = 4, private int $monthlyMonths = 12) {}
    public static function fromConfig(array $config): self { $r = is_array($config['recovery']['backups']['retention'] ?? null) ? $config['recovery']['backups']['retention'] : []; return new self((int)($r['daily_days'] ?? 7), (int)($r['weekly_weeks'] ?? 4), (int)($r['monthly_months'] ?? 12)); }
    public function keepSeconds(): int { return max($this->dailyDays * 86400, $this->weeklyWeeks * 7 * 86400, $this->monthlyMonths * 31 * 86400); }
}
