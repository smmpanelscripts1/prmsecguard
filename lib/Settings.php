<?php

namespace PrmSecGuard;

use Illuminate\Support\Facades\DB;
use Throwable;

class Settings
{
    public const KEY = 'prmsecguard::config';

    public static function defaults(): array
    {
        return [
            'enabled' => true,
            'retention_days' => 30,
            'cron_token' => '',
            'cron_interval_min' => 5,
            'last_cron_at' => 0,
            'allowlist' => [
                'ips' => [],
                'actor_ids' => [],
                'server_ids' => [],
            ],
            'mute_rules' => [],
            'notify' => [
                'enabled' => false,
                'min_severity' => 'high',
                'webhook_url' => '',
                'discord_webhook' => '',
                'telegram_bot_token' => '',
                'telegram_chat_id' => '',
                'auto_ban_auth_fail' => false,
            ],
            'mass_delete' => ['enabled' => true, 'threshold' => 8, 'window_sec' => 300],
            'mass_write' => ['enabled' => true, 'threshold' => 20, 'window_sec' => 300],
            'mass_download' => ['enabled' => true, 'threshold' => 15, 'window_sec' => 300],
            'sftp_new_ip' => ['enabled' => true, 'lookback_days' => 14],
            'sftp_night_new_ip' => ['enabled' => true, 'start_hour' => 0, 'end_hour' => 6, 'timezone' => 'Europe/Istanbul'],
            'api_key_burst' => ['enabled' => true, 'threshold' => 40, 'window_sec' => 60],
            'api_key_new_burst' => ['enabled' => true, 'age_sec' => 3600, 'threshold' => 20, 'window_sec' => 120],
            'off_hours_power' => ['enabled' => true, 'start_hour' => 0, 'end_hour' => 6, 'timezone' => 'Europe/Istanbul'],
            'auth_fail_burst' => ['enabled' => true, 'threshold' => 8, 'window_sec' => 600],
            'subuser_rapid' => ['enabled' => true, 'window_sec' => 900, 'action_threshold' => 5],
            'lateral_access' => ['enabled' => true, 'server_threshold' => 3, 'window_sec' => 600],
            'backup_burst' => ['enabled' => true, 'threshold' => 3, 'window_sec' => 600],
            'console_burst' => ['enabled' => true, 'threshold' => 25, 'window_sec' => 300],
            'console_ws' => ['enabled' => true, 'threshold' => 30, 'window_sec' => 300],
            'baseline' => [
                'enabled' => false,
                'per_server' => true,
                'lookback_days' => 7,
                'multiplier' => 3.0,
            ],
        ];
    }

    public static function get(): array
    {
        $defaults = self::defaults();
        try {
            $row = DB::table('settings')->where('key', self::KEY)->first();
            if (!$row) {
                return $defaults;
            }
            try {
                $parsed = unserialize($row->value);
            } catch (Throwable $e) {
                $parsed = json_decode((string) $row->value, true);
            }
            if (!is_array($parsed)) {
                return $defaults;
            }

            return self::merge($defaults, $parsed);
        } catch (Throwable $e) {
            return $defaults;
        }
    }

    public static function put(array $config): void
    {
        $merged = self::merge(self::defaults(), $config);
        // Preserve runtime fields if omitted.
        $current = self::get();
        if (!array_key_exists('last_cron_at', $config)) {
            $merged['last_cron_at'] = $current['last_cron_at'] ?? 0;
        }
        if (!array_key_exists('cron_token', $config) || $config['cron_token'] === null) {
            $merged['cron_token'] = $current['cron_token'] ?? '';
        }
        DB::table('settings')->updateOrInsert(
            ['key' => self::KEY],
            ['value' => serialize($merged)]
        );
    }

    public static function touchCron(): void
    {
        $cfg = self::get();
        $cfg['last_cron_at'] = time();
        self::put($cfg);
    }

    private static function merge(array $base, array $over): array
    {
        foreach ($over as $key => $value) {
            if (is_array($value) && isset($base[$key]) && is_array($base[$key]) && self::isAssoc($base[$key])) {
                $base[$key] = self::merge($base[$key], $value);
            } else {
                $base[$key] = $value;
            }
        }

        return $base;
    }

    private static function isAssoc(array $arr): bool
    {
        if ($arr === []) {
            return true;
        }

        return array_keys($arr) !== range(0, count($arr) - 1);
    }
}
