<?php

namespace PrmSecGuard;

class ConsoleStore
{
    public const KEEP_SECONDS = 7 * 86400;

    public static function path(): string
    {
        $env = trim((string) env('PRMSECGUARD_CONSOLE', getenv('PRMSECGUARD_CONSOLE') ?: ''));
        if ($env !== '') {
            return $env;
        }
        $candidates = [
            '/app/var/prmsecguard/console.jsonl',
            function_exists('storage_path') ? storage_path('app/prmsecguard/console.jsonl') : '',
            sys_get_temp_dir() . '/prmsecguard-console.jsonl',
        ];
        foreach ($candidates as $path) {
            if ($path === '') {
                continue;
            }
            $dir = dirname($path);
            if (is_dir($dir) || @mkdir($dir, 0775, true)) {
                return $path;
            }
        }

        return sys_get_temp_dir() . '/prmsecguard-console.jsonl';
    }

    public static function record(array $row): bool
    {
        $path = self::path();
        $dir = dirname($path);
        if (!is_dir($dir) && !@mkdir($dir, 0775, true)) {
            return false;
        }
        $entry = [
            'ts' => (int) ($row['ts'] ?? time()),
            'server_id' => isset($row['server_id']) ? (int) $row['server_id'] : null,
            'server_uuid' => (string) ($row['server_uuid'] ?? ''),
            'actor_id' => isset($row['actor_id']) ? (int) $row['actor_id'] : null,
            'ip' => (string) ($row['ip'] ?? ''),
            'command' => mb_substr((string) ($row['command'] ?? ''), 0, 500),
            'source' => (string) ($row['source'] ?? 'websocket'),
        ];
        $fh = @fopen($path, 'ab');
        if ($fh === false) {
            return false;
        }
        try {
            if (!flock($fh, LOCK_EX)) {
                return false;
            }
            fwrite($fh, json_encode($entry, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n");
            fflush($fh);
        } finally {
            flock($fh, LOCK_UN);
            fclose($fh);
        }

        return true;
    }

    public static function countInWindow(?int $serverId, $actorId, int $windowSec, ?int $until = null): int
    {
        $until = $until ?? time();
        $from = $until - max(15, $windowSec);
        $n = 0;
        foreach (self::recent(2000) as $row) {
            $ts = (int) ($row['ts'] ?? 0);
            if ($ts < $from || $ts > $until) {
                continue;
            }
            if ($serverId && (int) ($row['server_id'] ?? 0) !== $serverId) {
                continue;
            }
            if ($actorId && (int) ($row['actor_id'] ?? 0) !== (int) $actorId) {
                continue;
            }
            $n++;
        }

        return $n;
    }

    /** @return list<array> */
    public static function recent(int $limit = 100): array
    {
        $path = self::path();
        if (!is_file($path)) {
            return [];
        }
        $lines = @file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
        $cutoff = time() - self::KEEP_SECONDS;
        $out = [];
        for ($i = count($lines) - 1; $i >= 0; $i--) {
            $row = json_decode($lines[$i], true);
            if (!is_array($row)) {
                continue;
            }
            if ((int) ($row['ts'] ?? 0) < $cutoff) {
                break;
            }
            $out[] = $row;
            if (count($out) >= $limit) {
                break;
            }
        }

        return $out;
    }
}
