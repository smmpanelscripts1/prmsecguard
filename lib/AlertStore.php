<?php

namespace PrmSecGuard;

class AlertStore
{
    public const MAX_ALERTS = 3000;

    public static function path(): string
    {
        $env = trim((string) env('PRMSECGUARD_ALERTS', getenv('PRMSECGUARD_ALERTS') ?: ''));
        if ($env !== '') {
            return $env;
        }

        $candidates = [
            '/app/var/prmsecguard/alerts.jsonl',
            function_exists('storage_path') ? storage_path('app/prmsecguard/alerts.jsonl') : '',
            sys_get_temp_dir() . '/prmsecguard-alerts.jsonl',
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

        return sys_get_temp_dir() . '/prmsecguard-alerts.jsonl';
    }

    public static function keepSeconds(?array $cfg = null): int
    {
        $cfg = $cfg ?? Settings::get();
        $days = max(1, (int) ($cfg['retention_days'] ?? 30));

        return $days * 86400;
    }

    /** @return array|false */
    public static function append(array $alert, ?array $cfg = null)
    {
        $cfg = $cfg ?? Settings::get();
        $path = self::path();
        $dir = dirname($path);
        if (!is_dir($dir) && !@mkdir($dir, 0775, true)) {
            return false;
        }

        $fh = @fopen($path, 'c+');
        if ($fh === false) {
            return false;
        }

        try {
            if (!flock($fh, LOCK_EX)) {
                return false;
            }

            $fingerprint = (string) ($alert['fingerprint'] ?? '');
            if ($fingerprint !== '' && self::hasOpenFingerprint($fh, $fingerprint)) {
                return false;
            }

            $row = [
                'id' => bin2hex(random_bytes(8)),
                'ts' => (int) ($alert['ts'] ?? time()),
                'rule' => (string) ($alert['rule'] ?? 'unknown'),
                'severity' => (string) ($alert['severity'] ?? 'medium'),
                'title' => (string) ($alert['title'] ?? ''),
                'detail' => (string) ($alert['detail'] ?? ''),
                'event' => (string) ($alert['event'] ?? ''),
                'ip' => (string) ($alert['ip'] ?? ''),
                'actor_id' => $alert['actor_id'] ?? null,
                'server_id' => $alert['server_id'] ?? null,
                'api_key_id' => $alert['api_key_id'] ?? null,
                'activity_id' => $alert['activity_id'] ?? null,
                'count' => (int) ($alert['count'] ?? 1),
                'fingerprint' => $fingerprint,
                'acked' => false,
                'meta' => is_array($alert['meta'] ?? null) ? $alert['meta'] : [],
            ];

            fseek($fh, 0, SEEK_END);
            fwrite($fh, json_encode($row, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n");
            fflush($fh);

            return $row;
        } finally {
            if (is_resource($fh)) {
                flock($fh, LOCK_UN);
                fclose($fh);
            }
        }
    }

    public static function list(int $limit = 100, bool $openOnly = false, array $filters = []): array
    {
        $rows = [];
        $path = self::path();
        if (!is_file($path)) {
            return [];
        }

        $severity = strtolower((string) ($filters['severity'] ?? ''));
        $rule = (string) ($filters['rule'] ?? '');
        $q = strtolower(trim((string) ($filters['q'] ?? '')));

        $lines = @file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
        for ($i = count($lines) - 1; $i >= 0; $i--) {
            $row = json_decode($lines[$i], true);
            if (!is_array($row)) {
                continue;
            }
            if ($openOnly && !empty($row['acked'])) {
                continue;
            }
            if ($severity !== '' && strtolower((string) ($row['severity'] ?? '')) !== $severity) {
                continue;
            }
            if ($rule !== '' && (string) ($row['rule'] ?? '') !== $rule) {
                continue;
            }
            if ($q !== '') {
                $hay = strtolower(implode(' ', [
                    $row['title'] ?? '',
                    $row['detail'] ?? '',
                    $row['ip'] ?? '',
                    $row['rule'] ?? '',
                    $row['event'] ?? '',
                ]));
                if (!str_contains($hay, $q)) {
                    continue;
                }
            }
            $rows[] = $row;
            if (count($rows) >= $limit) {
                break;
            }
        }

        return $rows;
    }

    public static function find(string $id): ?array
    {
        foreach (self::list(self::MAX_ALERTS, false) as $row) {
            if (($row['id'] ?? '') === $id) {
                return $row;
            }
        }

        return null;
    }

    public static function openCount(): int
    {
        return count(self::list(self::MAX_ALERTS, true));
    }

    public static function report(): array
    {
        $byRule = [];
        $bySev = [];
        $open = 0;
        foreach (self::list(self::MAX_ALERTS, false) as $row) {
            $rule = (string) ($row['rule'] ?? 'unknown');
            $sev = (string) ($row['severity'] ?? 'medium');
            $byRule[$rule] = ($byRule[$rule] ?? 0) + 1;
            $bySev[$sev] = ($bySev[$sev] ?? 0) + 1;
            if (empty($row['acked'])) {
                $open++;
            }
        }

        return [
            'open' => $open,
            'by_rule' => $byRule,
            'by_severity' => $bySev,
            'ts' => time(),
        ];
    }

    public static function csv(array $filters = [], bool $openOnly = false): string
    {
        $rows = self::list(self::MAX_ALERTS, $openOnly, $filters);
        $lines = ['id,ts,iso,severity,rule,title,detail,event,ip,actor_id,server_id,api_key_id,activity_id,count,acked'];
        foreach ($rows as $r) {
            $lines[] = self::csvLine([
                $r['id'] ?? '',
                $r['ts'] ?? '',
                gmdate('c', (int) ($r['ts'] ?? 0)),
                $r['severity'] ?? '',
                $r['rule'] ?? '',
                $r['title'] ?? '',
                $r['detail'] ?? '',
                $r['event'] ?? '',
                $r['ip'] ?? '',
                $r['actor_id'] ?? '',
                $r['server_id'] ?? '',
                $r['api_key_id'] ?? '',
                $r['activity_id'] ?? '',
                $r['count'] ?? '',
                !empty($r['acked']) ? '1' : '0',
            ]);
        }

        return implode("\n", $lines) . "\n";
    }

    public static function ack(?string $id = null, bool $all = false): int
    {
        return self::rewrite(static function (array $row) use ($id, $all, &$changed) {
            if ($all || ($id !== null && ($row['id'] ?? '') === $id)) {
                if (empty($row['acked'])) {
                    $row['acked'] = true;
                    $row['acked_at'] = time();
                    $changed++;
                }
            }

            return $row;
        }, $changed);
    }

    public static function prune(?array $cfg = null): int
    {
        $keep = self::keepSeconds($cfg);
        $cutoff = time() - $keep;
        $removed = 0;
        self::rewrite(static function (array $row) use ($cutoff, &$removed) {
            if ((int) ($row['ts'] ?? 0) < $cutoff) {
                $removed++;

                return null;
            }

            return $row;
        });

        return $removed;
    }

    private static function rewrite(callable $fn, &$changed = 0): int
    {
        $changed = 0;
        $path = self::path();
        if (!is_file($path)) {
            return 0;
        }
        $fh = @fopen($path, 'c+');
        if ($fh === false) {
            return 0;
        }
        try {
            if (!flock($fh, LOCK_EX)) {
                return 0;
            }
            $raw = stream_get_contents($fh);
            $lines = preg_split("/\r\n|\n|\r/", (string) $raw) ?: [];
            $out = [];
            foreach ($lines as $line) {
                if ($line === '') {
                    continue;
                }
                $row = json_decode($line, true);
                if (!is_array($row)) {
                    continue;
                }
                $next = $fn($row);
                if ($next === null) {
                    continue;
                }
                $out[] = json_encode($next, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            }
            // Cap size.
            if (count($out) > self::MAX_ALERTS) {
                $out = array_slice($out, -self::MAX_ALERTS);
            }
            ftruncate($fh, 0);
            rewind($fh);
            fwrite($fh, implode("\n", $out) . (count($out) ? "\n" : ''));
            fflush($fh);
        } finally {
            flock($fh, LOCK_UN);
            fclose($fh);
        }

        return $changed;
    }

    private static function hasOpenFingerprint($fh, string $fingerprint): bool
    {
        $pos = ftell($fh);
        rewind($fh);
        $raw = stream_get_contents($fh);
        if ($pos !== false) {
            fseek($fh, $pos);
        }
        $lines = preg_split("/\r\n|\n|\r/", (string) $raw) ?: [];
        $window = time() - 3600;
        for ($i = count($lines) - 1; $i >= 0; $i--) {
            $row = json_decode($lines[$i], true);
            if (!is_array($row)) {
                continue;
            }
            if ((int) ($row['ts'] ?? 0) < $window) {
                break;
            }
            if (($row['fingerprint'] ?? '') === $fingerprint && empty($row['acked'])) {
                return true;
            }
        }

        return false;
    }

    private static function csvLine(array $cols): string
    {
        return implode(',', array_map(static function ($v) {
            $s = (string) $v;
            if (str_contains($s, ',') || str_contains($s, '"') || str_contains($s, "\n")) {
                return '"' . str_replace('"', '""', $s) . '"';
            }

            return $s;
        }, $cols));
    }
}
