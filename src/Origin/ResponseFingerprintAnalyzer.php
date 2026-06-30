<?php
namespace Mnb\SecurityCore\Origin;

class ResponseFingerprintAnalyzer
{
    public const RISKY_HEADERS = ['server','x-powered-by','x-generator','x-runtime','x-version','x-backend-server','x-origin-server','x-served-by','x-aspnet-version','x-aspnetmvc-version'];
    public function __construct(private array $riskyHeaders = self::RISKY_HEADERS) { $this->riskyHeaders = array_map('strtolower', $this->riskyHeaders); }
    public static function fromConfig(array $config): self
    {
        $origin = is_array($config['origin_protection'] ?? null) ? $config['origin_protection'] : [];
        $strip = array_map('strtolower', (array)($origin['strip_headers'] ?? []));
        return new self(array_values(array_unique(array_merge(self::RISKY_HEADERS, $strip))));
    }
    public function analyze(array $headers): FingerprintRiskReport
    {
        $findings = [];
        foreach ($headers as $name => $value) {
            $lower = strtolower((string)$name);
            if (in_array($lower, $this->riskyHeaders, true)) {
                $findings[] = ['header'=>(string)$name,'risk'=>'server_or_origin_fingerprint','value_summary'=>$this->summarize((string)$value)];
            } elseif (preg_match('/(origin|backend|server|runtime|version)/i', (string)$name)) {
                $findings[] = ['header'=>(string)$name,'risk'=>'suspicious_identity_header','value_summary'=>$this->summarize((string)$value)];
            }
        }
        return new FingerprintRiskReport($findings, min(100, count($findings) * 20));
    }
    private function summarize(string $value): string { return $value === '' ? '' : substr(preg_replace('/\d+\.\d+(?:\.\d+)*/', '[version]', $value) ?? $value, 0, 120); }
}
