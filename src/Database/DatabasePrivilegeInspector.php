<?php
namespace Mnb\SecurityCore\Database;

final class DatabasePrivilegeInspector
{
    private const DANGEROUS = ['DROP', 'ALTER', 'CREATE USER', 'GRANT', 'SUPER', 'FILE', 'SHUTDOWN', 'PROCESS', 'RELOAD'];

    public function __construct(private array $grantsOrPrivileges = []) {}

    /** @return array<string,mixed> */
    public function inspect(): array
    {
        $privileges = $this->extractPrivileges($this->grantsOrPrivileges);
        $dangerous = [];
        foreach ($privileges as $privilege) {
            foreach (self::DANGEROUS as $needle) {
                if (str_contains(strtoupper($privilege), $needle)) {
                    $dangerous[] = $needle;
                }
            }
        }
        $dangerous = array_values(array_unique($dangerous));
        return [
            'passed' => $dangerous === [],
            'dangerous_privileges' => $dangerous,
            'recommended_roles' => [
                'runtime_user' => ['SELECT', 'INSERT', 'UPDATE', 'DELETE'],
                'migration_user' => ['CREATE', 'ALTER', 'INDEX'],
                'readonly_user' => ['SELECT'],
            ],
            'message' => $dangerous === [] ? 'No dangerous database privileges were detected in supplied grants.' : 'Runtime database user appears too powerful; split runtime and migration credentials.',
        ];
    }

    /** @param array<int|string,mixed> $items @return array<int,string> */
    private function extractPrivileges(array $items): array
    {
        $text = strtoupper(implode(' ', array_map(static fn(mixed $v): string => is_scalar($v) ? (string)$v : json_encode($v), $items)));
        $out = [];
        foreach (['SELECT','INSERT','UPDATE','DELETE','CREATE','ALTER','DROP','INDEX','GRANT','SUPER','FILE','SHUTDOWN','PROCESS','RELOAD','CREATE USER'] as $priv) {
            if (str_contains($text, $priv)) {
                $out[] = $priv;
            }
        }
        return $out;
    }
}
