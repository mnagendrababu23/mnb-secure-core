<?php
namespace Mnb\SecurityCore\Incident;
final class IncidentSeverity { public const LOW='low'; public const MEDIUM='medium'; public const HIGH='high'; public const CRITICAL='critical'; public static function normalize(string $v): string { $v=strtolower($v); return in_array($v,[self::LOW,self::MEDIUM,self::HIGH,self::CRITICAL],true)?$v:self::MEDIUM; } }
