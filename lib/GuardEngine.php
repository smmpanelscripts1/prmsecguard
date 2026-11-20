<?php

namespace PrmSecGuard;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Pterodactyl\Events\ActivityLogged;
use Pterodactyl\Models\ActivityLog;
use Pterodactyl\Models\ApiKey;
use Pterodactyl\Models\Server;
use Throwable;

class GuardEngine
{
    private static bool $booted = false;
    private static array $baselineCache = [];

    public static function boot(): void
    {
        if (self::$booted) {
            return;
        }
        self::$booted = true;

        try {
            Event::listen(ActivityLogged::class, static function (ActivityLogged $event) {
                try {
                    self::onActivity($event->model);
                } catch (Throwable $e) {
                }
            });
        } catch (Throwable $e) {
        }
    }

    public static function onActivity(ActivityLog $log): void
    {
        $cfg = Settings::get();
        if (empty($cfg['enabled'])) {
            return;
        }

        $event = (string) $log->event;
        $serverId = self::serverId($log);
        $actorId = $log->actor_id;
        $ip = (string) $log->ip;
        $apiKeyId = $log->api_key_id;

        if (self::isAllowlisted($cfg, $ip, $actorId, $serverId)) {
            return;
        }

        if (self::isDeleteEvent($event)) {
            self::checkBurst($cfg, 'mass_delete', $log, $serverId, $actorId, [
                'server:file.delete', 'server:sftp.delete', 'server:database.delete',
            ], 'Toplu silme aktivitesi', 'silme');
        }

        if (self::isWriteEvent($event)) {
            self::checkBurst($cfg, 'mass_write', $log, $serverId, $actorId, [
                'server:file.write', 'server:file.upload', 'server:file.uploaded',
                'server:sftp.create', 'server:sftp.write', 'server:sftp.create-directory',
            ], 'Toplu yazma / upload', 'yazma');
        }

        if (self::isDownloadEvent($event)) {
            self::checkBurst($cfg, 'mass_download', $log, $serverId, $actorId, [
                'server:file.download', 'server:backup.download',
            ], 'Toplu indirme', 'indirme');
        }

        if (in_array($event, ['server:backup.delete', 'server:backup.restore', 'server:backup.restore-started'], true)
            || str_starts_with($event, 'server:backup.')) {
            if (in_array($event, ['server:backup.delete', 'server:backup.restore', 'server:backup.restore-started'], true)) {
                self::checkBurst($cfg, 'backup_burst', $log, $serverId, $actorId, [
                    'server:backup.delete', 'server:backup.restore', 'server:backup.restore-started',
                ], 'Backup delete/restore burst', 'backup işlemi');
            }
        }

        if (self::isSftpMutateEvent($event)) {
            $skipSftp = self::isHostingServer($serverId, $cfg) && empty($cfg['hosting']['cover_sftp_ip']);
            if (!$skipSftp) {
                self::checkSftpNewIp($cfg, $log, $serverId, $actorId, $ip);
            }
        }

        if ($apiKeyId) {
            self::checkApiKeyBurst($cfg, $log, (int) $apiKeyId);
            self::checkApiKeyNewBurst($cfg, $log, (int) $apiKeyId);
        }

        if (str_starts_with($event, 'server:power.')) {
            $hosting = self::isHostingServer($serverId, $cfg);
            if (!($hosting && !empty($cfg['hosting']['skip_off_hours_power']))) {
                self::checkOffHoursPower($cfg, $log, $serverId, $actorId);
            }
            self::checkSubuserRapid($cfg, $log, $serverId, $actorId);
            self::checkLateral($cfg, $log, $serverId, $actorId);
        }

        if (self::isFileOrSftpMutate($event)) {
            self::checkSubuserRapid($cfg, $log, $serverId, $actorId);
            self::checkLateral($cfg, $log, $serverId, $actorId);
        }

        if ($event === 'server:console.command') {
            self::checkBurst($cfg, 'console_burst', $log, $serverId, $actorId, [
                'server:console.command',
            ], 'Console komut patlaması (HTTP)', 'komut');
        }

        if ($event === 'server:subuser.create') {
            // Mark window; rapid actions checked on subsequent events.
            self::checkSubuserRapid($cfg, $log, $serverId, $actorId, true);
        }

        if (in_array($event, ['auth:fail', 'auth:sftp.fail', 'server:sftp.denied'], true)) {
            self::checkAuthFailBurst($cfg, $log, $ip);
        }
    }

    public static function scan(int $lookbackMinutes = 60): array
    {
        $cfg = Settings::get();
        if (empty($cfg['enabled'])) {
            return ['scanned' => 0, 'created' => 0, 'enabled' => false, 'open' => AlertStore::openCount()];
        }

        AlertStore::prune($cfg);

        $since = now()->subMinutes(max(5, $lookbackMinutes));
        $logs = ActivityLog::query()
            ->with('subjects')
            ->where('timestamp', '>=', $since)
            ->orderBy('id')
            ->limit(800)
            ->get();

        $before = AlertStore::openCount();
        foreach ($logs as $log) {
            try {
                self::onActivity($log);
            } catch (Throwable $e) {
            }
        }
        $after = AlertStore::openCount();

        return [
            'scanned' => $logs->count(),
            'created' => max(0, $after - $before),
            'enabled' => true,
            'open' => $after,
        ];
    }

    public static function emit(array $cfg, array $alert): void
    {
        $rule = (string) ($alert['rule'] ?? '');
        $muted = $cfg['mute_rules'] ?? [];
        if (is_array($muted) && in_array($rule, $muted, true)) {
            return;
        }

        if (self::isAllowlisted(
            $cfg,
            (string) ($alert['ip'] ?? ''),
            $alert['actor_id'] ?? null,
            isset($alert['server_id']) ? (int) $alert['server_id'] : null
        )) {
            return;
        }

        $sid = isset($alert['server_id']) ? (int) $alert['server_id'] : null;
        if ($sid && empty($alert['meta']['kind'])) {
            $alert['meta'] = is_array($alert['meta'] ?? null) ? $alert['meta'] : [];
            $alert['meta']['kind'] = self::isHostingServer($sid, $cfg) ? 'hosting' : 'game';
        }

        $row = AlertStore::append($alert, $cfg);
        if (!$row) {
            return;
        }

        try {
            Notifier::send($row, $cfg);
        } catch (Throwable $e) {
        }

        if ($rule === 'auth_fail_burst'
            && !empty($cfg['notify']['auto_ban_auth_fail'])
            && !empty($row['ip'])
        ) {
            try {
                BanBridge::ban((string) $row['ip'], 'SecGuard auth_fail_burst #' . ($row['id'] ?? ''));
            } catch (Throwable $e) {
            }
        }
    }

    private static function isAllowlisted(array $cfg, string $ip, $actorId, $serverId): bool
    {
        $al = $cfg['allowlist'] ?? [];
        $ips = array_map('strval', $al['ips'] ?? []);
        if ($ip !== '' && in_array($ip, $ips, true)) {
            return true;
        }
        $actors = array_map('intval', $al['actor_ids'] ?? []);
        if ($actorId && in_array((int) $actorId, $actors, true)) {
            return true;
        }
        $servers = array_map('intval', $al['server_ids'] ?? []);
        if ($serverId && in_array((int) $serverId, $servers, true)) {
            return true;
        }

        return false;
    }

    private static function threshold(array $cfg, string $ruleKey, int $base, string $eventFamily = '', ?int $serverId = null): int
    {
        $bl = $cfg['baseline'] ?? [];
        if (empty($bl['enabled']) || $eventFamily === '') {
            return $base;
        }
        $days = max(1, (int) ($bl['lookback_days'] ?? 7));
        $mult = max(1.0, (float) ($bl['multiplier'] ?? 3.0));
        $perServer = !empty($bl['per_server']);
        $avg = self::baselineAvg($eventFamily, $days, $perServer ? $serverId : null);
        if ($avg <= 0) {
            return $base;
        }
        $dyn = (int) ceil($avg * $mult);

        return max($base, $dyn);
    }

    private static function baselineAvg(string $family, int $days, ?int $serverId = null): float
    {
        $key = $family . ':' . $days . ':' . ($serverId ?? 'fleet');
        if (isset(self::$baselineCache[$key])) {
            return self::$baselineCache[$key];
        }
        try {
            $since = now()->subDays($days);
            $events = match ($family) {
                'delete' => ['server:file.delete', 'server:sftp.delete'],
                'write' => ['server:file.write', 'server:sftp.write', 'server:sftp.create'],
                'download' => ['server:file.download', 'server:backup.download'],
                default => [],
            };
            if ($events === []) {
                return self::$baselineCache[$key] = 0.0;
            }
            $q = ActivityLog::query()
                ->whereIn('event', $events)
                ->where('timestamp', '>=', $since);
            if ($serverId) {
                $q->whereHas('subjects', static function ($s) use ($serverId) {
                    $s->where('subject_type', 'server')->where('subject_id', $serverId);
                });
            }
            $count = (int) $q->count();
            // Average per 5-minute window over lookback for this server (or fleet).
            $windows = max(1, (int) floor(($days * 86400) / 300));

            return self::$baselineCache[$key] = $count / $windows;
        } catch (Throwable $e) {
            return self::$baselineCache[$key] = 0.0;
        }
    }

    /** Called after a websocket console sample is stored. */
    public static function onConsoleSample(array $cfg, ?int $serverId, $actorId, string $ip): void
    {
        $rule = $cfg['console_ws'] ?? [];
        if (empty($rule['enabled']) || !class_exists(ConsoleStore::class)) {
            return;
        }
        $threshold = max(5, (int) ($rule['threshold'] ?? 30));
        $window = max(30, (int) ($rule['window_sec'] ?? 300));
        $count = ConsoleStore::countInWindow($serverId, $actorId, $window);
        if ($count < $threshold) {
            return;
        }
        $bucket = (int) floor(time() / $window);
        self::emit($cfg, [
            'ts' => time(),
            'rule' => 'console_ws',
            'severity' => $count >= $threshold * 2 ? 'critical' : 'high',
            'title' => 'Websocket console komut patlaması',
            'detail' => sprintf('%d WS komut / %d sn (eşik %d).', $count, $window, $threshold),
            'event' => 'server:console.websocket',
            'ip' => $ip,
            'actor_id' => $actorId,
            'server_id' => $serverId,
            'api_key_id' => null,
            'activity_id' => null,
            'count' => $count,
            'fingerprint' => "console_ws:{$actorId}:{$serverId}:{$bucket}",
        ]);
    }

    private static function checkBurst(
        array $cfg,
        string $ruleKey,
        ActivityLog $log,
        ?int $serverId,
        $actorId,
        array $events,
        string $title,
        string $label
    ): void {
        $rule = $cfg[$ruleKey] ?? [];
        if (empty($rule['enabled'])) {
            return;
        }
        $base = max(2, (int) ($rule['threshold'] ?? 8));
        $family = match ($ruleKey) {
            'mass_delete' => 'delete',
            'mass_write' => 'write',
            'mass_download' => 'download',
            default => '',
        };
        // Hosting sites: tighter file burst thresholds when enabled.
        if (in_array($ruleKey, ['mass_delete', 'mass_write', 'mass_download'], true)
            && self::isHostingServer($serverId, $cfg)
            && !empty($cfg['hosting']['cover_file_burst'])) {
            $scale = (float) ($cfg['hosting']['file_threshold_scale'] ?? 0.75);
            if ($scale > 0 && $scale < 1.5) {
                $base = max(2, (int) round($base * $scale));
            }
        }
        $threshold = self::threshold($cfg, $ruleKey, $base, $family, $serverId);
        $window = max(30, (int) ($rule['window_sec'] ?? 300));
        $since = $log->timestamp->copy()->subSeconds($window);

        $q = ActivityLog::query()
            ->whereIn('event', $events)
            ->where('timestamp', '>=', $since)
            ->where('timestamp', '<=', $log->timestamp);

        if ($actorId) {
            $q->where('actor_id', $actorId)->where('actor_type', $log->actor_type);
        } else {
            $q->where('ip', $log->ip);
        }
        if ($serverId) {
            $q->whereHas('subjects', static function ($s) use ($serverId) {
                $s->where('subject_type', 'server')->where('subject_id', $serverId);
            });
        }

        $count = (int) $q->count();
        if ($count < $threshold) {
            return;
        }

        $bucket = (int) floor($log->timestamp->getTimestamp() / $window);
        $scope = (!empty($cfg['baseline']['enabled']) && !empty($cfg['baseline']['per_server']) && $serverId)
            ? ' (sunucu baseline)'
            : '';
        self::emit($cfg, [
            'ts' => $log->timestamp->getTimestamp(),
            'rule' => $ruleKey,
            'severity' => $count >= $threshold * 2 ? 'critical' : 'high',
            'title' => $title,
            'detail' => sprintf('%d %s / %d sn (eşik %d)%s.', $count, $label, $window, $threshold, $scope),
            'event' => $log->event,
            'ip' => $log->ip,
            'actor_id' => $actorId,
            'server_id' => $serverId,
            'api_key_id' => $log->api_key_id,
            'activity_id' => $log->id,
            'count' => $count,
            'fingerprint' => "{$ruleKey}:{$actorId}:{$serverId}:{$bucket}",
        ]);
    }

    private static function checkSftpNewIp(array $cfg, ActivityLog $log, ?int $serverId, $actorId, string $ip): void
    {
        $rule = $cfg['sftp_new_ip'] ?? [];
        if (empty($rule['enabled']) || $ip === '' || $ip === '127.0.0.1') {
            return;
        }
        $days = max(1, (int) ($rule['lookback_days'] ?? 14));
        $since = now()->subDays($days);

        $prior = ActivityLog::query()
            ->where('ip', $ip)
            ->where('timestamp', '>=', $since)
            ->where('timestamp', '<', $log->timestamp)
            ->where(static function ($q) {
                $q->where('event', 'like', 'server:sftp.%')->orWhere('event', 'like', 'auth:%');
            });
        if ($actorId) {
            $prior->where('actor_id', $actorId);
        }
        if ($prior->exists()) {
            return;
        }

        $severity = 'high';
        $night = $cfg['sftp_night_new_ip'] ?? [];
        if (!empty($night['enabled']) && self::inHours($log, $night)) {
            $severity = 'critical';
        }

        self::emit($cfg, [
            'ts' => $log->timestamp->getTimestamp(),
            'rule' => 'sftp_new_ip',
            'severity' => $severity,
            'title' => $severity === 'critical' ? 'Gece yeni IP SFTP' : 'Yeni IP üzerinden SFTP',
            'detail' => sprintf('IP %s son %d günde görülmedi%s.', $ip, $days, $severity === 'critical' ? ' + mesai dışı' : ''),
            'event' => $log->event,
            'ip' => $ip,
            'actor_id' => $actorId,
            'server_id' => $serverId,
            'api_key_id' => $log->api_key_id,
            'activity_id' => $log->id,
            'count' => 1,
            'fingerprint' => "sftp_new_ip:{$actorId}:{$serverId}:{$ip}",
        ]);
    }

    private static function checkApiKeyBurst(array $cfg, ActivityLog $log, int $apiKeyId): void
    {
        $rule = $cfg['api_key_burst'] ?? [];
        if (empty($rule['enabled'])) {
            return;
        }
        $threshold = max(5, (int) ($rule['threshold'] ?? 40));
        $window = max(15, (int) ($rule['window_sec'] ?? 60));
        $since = $log->timestamp->copy()->subSeconds($window);
        $count = (int) ActivityLog::query()
            ->where('api_key_id', $apiKeyId)
            ->where('timestamp', '>=', $since)
            ->where('timestamp', '<=', $log->timestamp)
            ->count();
        if ($count < $threshold) {
            return;
        }
        $bucket = (int) floor($log->timestamp->getTimestamp() / $window);
        self::emit($cfg, [
            'ts' => $log->timestamp->getTimestamp(),
            'rule' => 'api_key_burst',
            'severity' => 'high',
            'title' => 'API key kullanım patlaması',
            'detail' => sprintf('API key #%d ile %d olay / %d sn.', $apiKeyId, $count, $window),
            'event' => $log->event,
            'ip' => $log->ip,
            'actor_id' => $log->actor_id,
            'server_id' => self::serverId($log),
            'api_key_id' => $apiKeyId,
            'activity_id' => $log->id,
            'count' => $count,
            'fingerprint' => "api_key_burst:{$apiKeyId}:{$bucket}",
        ]);
    }

    private static function checkApiKeyNewBurst(array $cfg, ActivityLog $log, int $apiKeyId): void
    {
        $rule = $cfg['api_key_new_burst'] ?? [];
        if (empty($rule['enabled'])) {
            return;
        }
        try {
            $key = ApiKey::query()->find($apiKeyId);
            if (!$key || !$key->created_at) {
                return;
            }
            $ageSec = max(60, (int) ($rule['age_sec'] ?? 3600));
            if ($key->created_at->lt(now()->subSeconds($ageSec))) {
                return;
            }
        } catch (Throwable $e) {
            return;
        }

        $threshold = max(5, (int) ($rule['threshold'] ?? 20));
        $window = max(15, (int) ($rule['window_sec'] ?? 120));
        $since = $log->timestamp->copy()->subSeconds($window);
        $count = (int) ActivityLog::query()
            ->where('api_key_id', $apiKeyId)
            ->where('timestamp', '>=', $since)
            ->where('timestamp', '<=', $log->timestamp)
            ->count();
        if ($count < $threshold) {
            return;
        }
        $bucket = (int) floor($log->timestamp->getTimestamp() / $window);
        self::emit($cfg, [
            'ts' => $log->timestamp->getTimestamp(),
            'rule' => 'api_key_new_burst',
            'severity' => 'critical',
            'title' => 'Yeni API key + yoğun kullanım',
            'detail' => sprintf('Key #%d yeni (%ds) ve %d olay / %ds.', $apiKeyId, $ageSec ?? 3600, $count, $window),
            'event' => $log->event,
            'ip' => $log->ip,
            'actor_id' => $log->actor_id,
            'server_id' => self::serverId($log),
            'api_key_id' => $apiKeyId,
            'activity_id' => $log->id,
            'count' => $count,
            'fingerprint' => "api_key_new_burst:{$apiKeyId}:{$bucket}",
        ]);
    }

    private static function checkOffHoursPower(array $cfg, ActivityLog $log, ?int $serverId, $actorId): void
    {
        $rule = $cfg['off_hours_power'] ?? [];
        if (empty($rule['enabled']) || !self::inHours($log, $rule)) {
            return;
        }
        try {
            $tz = (string) ($rule['timezone'] ?? 'Europe/Istanbul');
            $local = $log->timestamp->copy()->timezone($tz);
        } catch (Throwable $e) {
            $local = $log->timestamp->copy();
            $tz = 'UTC';
        }
        $day = $local->format('Y-m-d');
        self::emit($cfg, [
            'ts' => $log->timestamp->getTimestamp(),
            'rule' => 'off_hours_power',
            'severity' => 'medium',
            'title' => 'Mesai dışı power işlemi',
            'detail' => sprintf('%s saati %s (%s).', $log->event, $local->format('H:i'), $tz),
            'event' => $log->event,
            'ip' => $log->ip,
            'actor_id' => $actorId,
            'server_id' => $serverId,
            'api_key_id' => $log->api_key_id,
            'activity_id' => $log->id,
            'count' => 1,
            'fingerprint' => "off_hours_power:{$serverId}:{$actorId}:{$day}:{$log->event}",
        ]);
    }

    private static function checkAuthFailBurst(array $cfg, ActivityLog $log, string $ip): void
    {
        $rule = $cfg['auth_fail_burst'] ?? [];
        if (empty($rule['enabled'])) {
            return;
        }
        $threshold = max(3, (int) ($rule['threshold'] ?? 8));
        $window = max(60, (int) ($rule['window_sec'] ?? 600));
        $since = $log->timestamp->copy()->subSeconds($window);
        $count = (int) ActivityLog::query()
            ->whereIn('event', ['auth:fail', 'auth:sftp.fail', 'server:sftp.denied'])
            ->where('ip', $ip)
            ->where('timestamp', '>=', $since)
            ->where('timestamp', '<=', $log->timestamp)
            ->count();
        if ($count < $threshold) {
            return;
        }
        $bucket = (int) floor($log->timestamp->getTimestamp() / $window);
        self::emit($cfg, [
            'ts' => $log->timestamp->getTimestamp(),
            'rule' => 'auth_fail_burst',
            'severity' => $count >= $threshold * 2 ? 'critical' : 'high',
            'title' => 'Başarısız giriş / SFTP denemesi',
            'detail' => sprintf('IP %s için %d başarısız deneme / %d sn.', $ip, $count, $window),
            'event' => $log->event,
            'ip' => $ip,
            'actor_id' => $log->actor_id,
            'server_id' => null,
            'api_key_id' => $log->api_key_id,
            'activity_id' => $log->id,
            'count' => $count,
            'fingerprint' => "auth_fail_burst:{$ip}:{$bucket}",
            'meta' => ['can_ban' => true],
        ]);
    }

    private static function checkSubuserRapid(array $cfg, ActivityLog $log, ?int $serverId, $actorId, bool $fromCreate = false): void
    {
        $rule = $cfg['subuser_rapid'] ?? [];
        if (empty($rule['enabled']) || !$serverId) {
            return;
        }
        $window = max(60, (int) ($rule['window_sec'] ?? 900));
        $threshold = max(2, (int) ($rule['action_threshold'] ?? 5));
        $since = $log->timestamp->copy()->subSeconds($window);

        $created = ActivityLog::query()
            ->where('event', 'server:subuser.create')
            ->where('timestamp', '>=', $since)
            ->where('timestamp', '<=', $log->timestamp)
            ->whereHas('subjects', static function ($s) use ($serverId) {
                $s->where('subject_type', 'server')->where('subject_id', $serverId);
            })
            ->exists();
        if (!$created && !$fromCreate) {
            return;
        }

        $actions = (int) ActivityLog::query()
            ->where('timestamp', '>=', $since)
            ->where('timestamp', '<=', $log->timestamp)
            ->where(static function ($q) {
                $q->where('event', 'like', 'server:power.%')
                    ->orWhere('event', 'like', 'server:file.%')
                    ->orWhere('event', 'like', 'server:sftp.%');
            })
            ->whereHas('subjects', static function ($s) use ($serverId) {
                $s->where('subject_type', 'server')->where('subject_id', $serverId);
            })
            ->count();

        if ($actions < $threshold) {
            return;
        }

        $bucket = (int) floor($log->timestamp->getTimestamp() / $window);
        self::emit($cfg, [
            'ts' => $log->timestamp->getTimestamp(),
            'rule' => 'subuser_rapid',
            'severity' => 'high',
            'title' => 'Subuser sonrası hızlı işlem',
            'detail' => sprintf('Subuser create sonrası %d power/file/SFTP / %ds.', $actions, $window),
            'event' => $log->event,
            'ip' => $log->ip,
            'actor_id' => $actorId,
            'server_id' => $serverId,
            'api_key_id' => $log->api_key_id,
            'activity_id' => $log->id,
            'count' => $actions,
            'fingerprint' => "subuser_rapid:{$serverId}:{$bucket}",
        ]);
    }

    private static function checkLateral(array $cfg, ActivityLog $log, ?int $serverId, $actorId): void
    {
        $rule = $cfg['lateral_access'] ?? [];
        if (empty($rule['enabled']) || !$actorId) {
            return;
        }
        $threshold = max(2, (int) ($rule['server_threshold'] ?? 3));
        $window = max(60, (int) ($rule['window_sec'] ?? 600));
        $since = $log->timestamp->copy()->subSeconds($window);

        $serverIds = DB::table('activity_logs as a')
            ->join('activity_log_subjects as s', 's.activity_log_id', '=', 'a.id')
            ->where('a.actor_id', $actorId)
            ->where('a.timestamp', '>=', $since)
            ->where('a.timestamp', '<=', $log->timestamp)
            ->where('s.subject_type', 'server')
            ->where(static function ($q) {
                $q->where('a.event', 'like', 'server:power.%')
                    ->orWhere('a.event', 'like', 'server:file.%')
                    ->orWhere('a.event', 'like', 'server:sftp.%');
            })
            ->distinct()
            ->pluck('s.subject_id');

        $n = $serverIds->count();
        if ($n < $threshold) {
            return;
        }
        $bucket = (int) floor($log->timestamp->getTimestamp() / $window);
        self::emit($cfg, [
            'ts' => $log->timestamp->getTimestamp(),
            'rule' => 'lateral_access',
            'severity' => 'critical',
            'title' => 'Çoklu sunucu (lateral) erişim',
            'detail' => sprintf('Aktör #%s %d sn içinde %d sunucuya müdahale etti.', $actorId, $window, $n),
            'event' => $log->event,
            'ip' => $log->ip,
            'actor_id' => $actorId,
            'server_id' => $serverId,
            'api_key_id' => $log->api_key_id,
            'activity_id' => $log->id,
            'count' => $n,
            'fingerprint' => "lateral_access:{$actorId}:{$bucket}",
            'meta' => ['server_ids' => $serverIds->values()->all()],
        ]);
    }

    private static function inHours(ActivityLog $log, array $rule): bool
    {
        $start = (int) ($rule['start_hour'] ?? 0);
        $end = (int) ($rule['end_hour'] ?? 6);
        $tz = (string) ($rule['timezone'] ?? 'Europe/Istanbul');
        try {
            $local = $log->timestamp->copy()->timezone($tz);
        } catch (Throwable $e) {
            $local = $log->timestamp->copy();
        }
        $hour = (int) $local->format('G');
        if ($start === $end) {
            return false;
        }

        return $start < $end
            ? ($hour >= $start && $hour < $end)
            : ($hour >= $start || $hour < $end);
    }

    private static function isDeleteEvent(string $event): bool
    {
        return in_array($event, ['server:file.delete', 'server:sftp.delete', 'server:database.delete'], true);
    }

    private static function isWriteEvent(string $event): bool
    {
        return in_array($event, [
            'server:file.write', 'server:file.upload', 'server:file.uploaded',
            'server:sftp.create', 'server:sftp.write', 'server:sftp.create-directory',
        ], true);
    }

    private static function isDownloadEvent(string $event): bool
    {
        return in_array($event, ['server:file.download', 'server:backup.download'], true);
    }

    private static function isSftpMutateEvent(string $event): bool
    {
        return in_array($event, [
            'server:sftp.create', 'server:sftp.write', 'server:sftp.delete',
            'server:sftp.create-directory', 'server:sftp.rename',
        ], true);
    }

    private static function isFileOrSftpMutate(string $event): bool
    {
        return str_starts_with($event, 'server:file.') || str_starts_with($event, 'server:sftp.');
    }

    private static function serverId(ActivityLog $log): ?int
    {
        try {
            foreach ($log->subjects as $subject) {
                if ($subject->subject_type === 'server') {
                    return (int) $subject->subject_id;
                }
            }
        } catch (Throwable $e) {
        }
        try {
            $row = DB::table('activity_log_subjects')
                ->where('activity_log_id', $log->id)
                ->where('subject_type', 'server')
                ->first();
            if ($row) {
                return (int) $row->subject_id;
            }
        } catch (Throwable $e) {
        }

        return null;
    }

    /**
     * Nest/egg id lists for hosting (web) servers. Empty lists auto-fill from prmhosting.
     *
     * @return array{eggIds: list<int>, nestIds: list<int>}
     */
    private static function hostingIds(array $cfg): array
    {
        $h = is_array($cfg['hosting'] ?? null) ? $cfg['hosting'] : [];
        $eggIds = array_values(array_unique(array_filter(array_map('intval', $h['egg_ids'] ?? []))));
        $nestIds = array_values(array_unique(array_filter(array_map('intval', $h['nest_ids'] ?? []))));

        if ($eggIds === [] && $nestIds === []) {
            try {
                $hostSettings = '/blueprint_extensions/prmhosting/lib/Settings.php';
                if (!class_exists(\PrmHosting\Settings::class) && is_file($hostSettings)) {
                    require_once $hostSettings;
                }
                if (class_exists(\PrmHosting\Settings::class)) {
                    $hs = \PrmHosting\Settings::get();
                    if (!empty($hs['egg_id'])) {
                        $eggIds[] = (int) $hs['egg_id'];
                    }
                    if (!empty($hs['nest_id'])) {
                        $nestIds[] = (int) $hs['nest_id'];
                    }
                }
            } catch (Throwable $e) {
            }
        }

        return ['eggIds' => $eggIds, 'nestIds' => $nestIds];
    }

    private static function isHostingServer(?int $serverId, array $cfg): bool
    {
        if (!$serverId || empty($cfg['hosting']['enabled'])) {
            return false;
        }
        $ids = self::hostingIds($cfg);
        if ($ids['eggIds'] === [] && $ids['nestIds'] === []) {
            return false;
        }
        try {
            $server = Server::query()->find($serverId, ['id', 'egg_id', 'nest_id']);
            if (!$server) {
                return false;
            }
            if ($ids['eggIds'] !== [] && in_array((int) $server->egg_id, $ids['eggIds'], true)) {
                return true;
            }
            if ($ids['nestIds'] !== [] && in_array((int) $server->nest_id, $ids['nestIds'], true)) {
                return true;
            }
        } catch (Throwable $e) {
        }

        return false;
    }
}
