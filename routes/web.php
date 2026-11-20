<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Pterodactyl\Http\Middleware\AdminAuthenticate;
use Pterodactyl\Models\ActivityLog;
use Pterodactyl\Models\Server;
use Pterodactyl\Models\User;

$prmSecGuardLoad = static function (): void {
    $base = '/blueprint_extensions/prmsecguard/lib';
    foreach (['Settings.php', 'AlertStore.php', 'Notifier.php', 'BanBridge.php', 'ConsoleStore.php', 'GuardEngine.php', 'HostFirewall.php'] as $file) {
        $path = $base . '/' . $file;
        if (is_file($path)) {
            require_once $path;
        }
    }
    if (class_exists(\PrmSecGuard\GuardEngine::class)) {
        \PrmSecGuard\GuardEngine::boot();
    }
};

$tokenOk = static function (Request $request): bool {
    $cfg = \PrmSecGuard\Settings::get();
    $token = (string) ($cfg['cron_token'] ?? '');
    $given = (string) ($request->query('token') ?: $request->input('token') ?: $request->header('X-SecGuard-Token') ?: '');

    return $token !== '' && hash_equals($token, $given);
};

$prmSecGuardLoad();

$resolveNames = static function (array $alerts): array {
    $serverIds = [];
    $userIds = [];
    foreach ($alerts as $a) {
        if (!empty($a['server_id'])) {
            $serverIds[] = (int) $a['server_id'];
        }
        if (!empty($a['actor_id'])) {
            $userIds[] = (int) $a['actor_id'];
        }
    }
    $servers = $serverIds
        ? Server::query()->whereIn('id', array_unique($serverIds))->get(['id', 'name', 'uuidShort'])->keyBy('id')
        : collect();
    $users = $userIds
        ? User::query()->whereIn('id', array_unique($userIds))->get(['id', 'username', 'email'])->keyBy('id')
        : collect();

    return array_map(static function ($a) use ($servers, $users) {
        $sid = isset($a['server_id']) ? (int) $a['server_id'] : null;
        $uid = isset($a['actor_id']) ? (int) $a['actor_id'] : null;
        $a['server_name'] = $sid && $servers->has($sid)
            ? ($servers[$sid]->name . ' (' . $servers[$sid]->uuidShort . ')')
            : null;
        $a['actor_name'] = $uid && $users->has($uid)
            ? ($users[$uid]->username ?: $users[$uid]->email)
            : null;
        $a['ban_available'] = class_exists(\PrmSecGuard\BanBridge::class) && \PrmSecGuard\BanBridge::available();

        return $a;
    }, $alerts);
};

$ruleKeys = [
    'mass_delete', 'mass_write', 'mass_download', 'sftp_new_ip', 'sftp_night_new_ip',
    'api_key_burst', 'api_key_new_burst', 'off_hours_power', 'auth_fail_burst',
    'subuser_rapid', 'lateral_access', 'backup_burst', 'console_burst', 'baseline',
];

Route::get('/status', function () use ($prmSecGuardLoad, $resolveNames) {
    $prmSecGuardLoad();
    $cfg = \PrmSecGuard\Settings::get();

    return response()->json([
        'enabled' => !empty($cfg['enabled']),
        'open_count' => \PrmSecGuard\AlertStore::openCount(),
        'recent_open' => $resolveNames(\PrmSecGuard\AlertStore::list(8, true)),
        'config' => $cfg,
        'ban_available' => \PrmSecGuard\BanBridge::available(),
        'report' => \PrmSecGuard\AlertStore::report(),
    ]);
})->middleware(['auth', AdminAuthenticate::class]);

Route::get('/alerts', function (Request $request) use ($prmSecGuardLoad, $resolveNames) {
    $prmSecGuardLoad();
    $openOnly = $request->boolean('open', false);
    $limit = min(500, max(1, (int) $request->query('limit', 100)));
    $filters = [
        'severity' => (string) $request->query('severity', ''),
        'rule' => (string) $request->query('rule', ''),
        'kind' => (string) $request->query('kind', ''),
        'q' => (string) $request->query('q', ''),
    ];
    $alerts = $resolveNames(\PrmSecGuard\AlertStore::list($limit, $openOnly, $filters));

    return response()->json([
        'alerts' => $alerts,
        'open_count' => \PrmSecGuard\AlertStore::openCount(),
    ]);
})->middleware(['auth', AdminAuthenticate::class]);

Route::get('/alerts/{id}/context', function (string $id) use ($prmSecGuardLoad) {
    $prmSecGuardLoad();
    $alert = \PrmSecGuard\AlertStore::find($id);
    if (!$alert) {
        return response()->json(['message' => 'Alert yok'], 404);
    }

    $q = ActivityLog::query()->with('subjects')->orderByDesc('id')->limit(10);
    if (!empty($alert['activity_id'])) {
        $center = ActivityLog::query()->find($alert['activity_id']);
        if ($center) {
            $q->where('timestamp', '>=', $center->timestamp->copy()->subMinutes(30))
                ->where('timestamp', '<=', $center->timestamp->copy()->addMinutes(5));
        }
    }
    if (!empty($alert['actor_id'])) {
        $q->where('actor_id', (int) $alert['actor_id']);
    } elseif (!empty($alert['ip'])) {
        $q->where('ip', $alert['ip']);
    }
    if (!empty($alert['server_id'])) {
        $sid = (int) $alert['server_id'];
        $q->whereHas('subjects', static function ($s) use ($sid) {
            $s->where('subject_type', 'server')->where('subject_id', $sid);
        });
    }

    $rows = $q->get()->map(static function (ActivityLog $log) {
        return [
            'id' => $log->id,
            'event' => $log->event,
            'ip' => $log->ip,
            'actor_id' => $log->actor_id,
            'api_key_id' => $log->api_key_id,
            'ts' => optional($log->timestamp)->getTimestamp(),
            'properties' => $log->properties,
        ];
    })->values();

    return response()->json(['alert' => $alert, 'activity' => $rows]);
})->middleware(['auth', AdminAuthenticate::class]);

Route::get('/alerts.csv', function (Request $request) use ($prmSecGuardLoad) {
    $prmSecGuardLoad();
    $csv = \PrmSecGuard\AlertStore::csv([
        'severity' => (string) $request->query('severity', ''),
        'rule' => (string) $request->query('rule', ''),
        'q' => (string) $request->query('q', ''),
    ], $request->boolean('open', false));

    return response($csv, 200, [
        'Content-Type' => 'text/csv; charset=UTF-8',
        'Content-Disposition' => 'attachment; filename="prmsecguard-alerts.csv"',
    ]);
})->middleware(['auth', AdminAuthenticate::class]);

$fleetReport = static function () {
    $report = \PrmSecGuard\AlertStore::report();
    $report['console_samples_recent'] = count(\PrmSecGuard\ConsoleStore::recent(200));
    $report['baseline'] = \PrmSecGuard\Settings::get()['baseline'] ?? [];
    $report['servers'] = Server::query()->count();
    $open = \PrmSecGuard\AlertStore::list(50, true);
    $report['recent_open'] = array_map(static function ($a) {
        return [
            'id' => $a['id'] ?? null,
            'ts' => $a['ts'] ?? null,
            'rule' => $a['rule'] ?? null,
            'severity' => $a['severity'] ?? null,
            'title' => $a['title'] ?? null,
            'server_id' => $a['server_id'] ?? null,
            'ip' => $a['ip'] ?? null,
        ];
    }, $open);

    return $report;
};

Route::get('/report', function () use ($prmSecGuardLoad, $fleetReport) {
    $prmSecGuardLoad();

    return response()->json($fleetReport());
})->middleware(['auth', AdminAuthenticate::class]);

Route::match(['GET', 'POST'], '/fleet', function (Request $request) use ($prmSecGuardLoad, $tokenOk, $fleetReport) {
    $prmSecGuardLoad();
    if (!$tokenOk($request)) {
        return response()->json(['message' => 'Unauthorized'], 401);
    }

    return response()->json($fleetReport());
});

Route::post('/console-sample', function (Request $request) use ($prmSecGuardLoad, $tokenOk) {
    $prmSecGuardLoad();
    $viaToken = $tokenOk($request);
    if (!$viaToken && !auth()->check()) {
        return response()->json(['message' => 'Unauthorized'], 401);
    }

    $data = $request->validate([
        'server_uuid' => 'nullable|string|max:64',
        'server_id' => 'nullable|integer',
        'command' => 'required|string|max:500',
        'source' => 'nullable|string|max:32',
        'actor_id' => 'nullable|integer',
        'ip' => 'nullable|string|max:64',
    ]);

    $server = null;
    if (!empty($data['server_id'])) {
        $server = Server::query()->find((int) $data['server_id']);
    } elseif (!empty($data['server_uuid'])) {
        $uuid = $data['server_uuid'];
        $server = Server::query()
            ->where('uuid', $uuid)
            ->orWhere('uuidShort', $uuid)
            ->orWhere('uuid', 'like', $uuid . '%')
            ->first();
    }
    if (!$server) {
        return response()->json(['message' => 'Server not found'], 404);
    }

    // Token callers (Next panel) have no session CSRF; session callers still require login above.
    $actorId = $viaToken
        ? ($data['actor_id'] ?? null)
        : (auth()->id());
    $ip = $viaToken
        ? (string) ($data['ip'] ?? $request->ip())
        : (string) $request->ip();

    \PrmSecGuard\ConsoleStore::record([
        'server_id' => $server->id,
        'server_uuid' => $server->uuid,
        'actor_id' => $actorId,
        'ip' => $ip,
        'command' => $data['command'],
        'source' => $data['source'] ?? 'websocket',
    ]);

    $cfg = \PrmSecGuard\Settings::get();
    \PrmSecGuard\GuardEngine::onConsoleSample($cfg, (int) $server->id, $actorId, $ip);

    return response()->json(['ok' => true]);
})->withoutMiddleware([\Pterodactyl\Http\Middleware\VerifyCsrfToken::class]);

Route::post('/ack', function (Request $request) use ($prmSecGuardLoad) {
    $prmSecGuardLoad();
    $data = $request->validate([
        'id' => 'nullable|string|max:64',
        'all' => 'nullable|boolean',
    ]);
    $changed = !empty($data['all'])
        ? \PrmSecGuard\AlertStore::ack(null, true)
        : \PrmSecGuard\AlertStore::ack($data['id'] ?? null, false);

    return response()->json([
        'acked' => $changed,
        'open_count' => \PrmSecGuard\AlertStore::openCount(),
    ]);
})->middleware(['auth', AdminAuthenticate::class]);

Route::post('/ban', function (Request $request) use ($prmSecGuardLoad) {
    $prmSecGuardLoad();
    $data = $request->validate([
        'ip' => 'required|string|max:64',
        'note' => 'nullable|string|max:120',
        'alert_id' => 'nullable|string|max:64',
    ]);
    $result = \PrmSecGuard\BanBridge::ban($data['ip'], $data['note'] ?? 'SecGuard manual');
    if (!empty($data['alert_id'])) {
        \PrmSecGuard\AlertStore::ack($data['alert_id'], false);
    }

    return response()->json($result + ['open_count' => \PrmSecGuard\AlertStore::openCount()]);
})->middleware(['auth', AdminAuthenticate::class]);

Route::post('/scan', function (Request $request) use ($prmSecGuardLoad) {
    $prmSecGuardLoad();
    $minutes = min(24 * 60, max(5, (int) $request->input('minutes', 60)));

    return response()->json(\PrmSecGuard\GuardEngine::scan($minutes));
})->middleware(['auth', AdminAuthenticate::class]);

Route::match(['GET', 'POST'], '/cron', function (Request $request) use ($prmSecGuardLoad) {
    $prmSecGuardLoad();
    $cfg = \PrmSecGuard\Settings::get();
    $token = (string) ($cfg['cron_token'] ?? '');
    $given = (string) ($request->query('token') ?: $request->input('token') ?: '');
    if ($token === '' || !hash_equals($token, $given)) {
        return response()->json(['message' => 'Unauthorized'], 401);
    }
    $interval = max(1, (int) ($cfg['cron_interval_min'] ?? 5));
    $last = (int) ($cfg['last_cron_at'] ?? 0);
    if ($last > 0 && (time() - $last) < ($interval * 60 - 15)) {
        return response()->json([
            'skipped' => true,
            'reason' => 'interval',
            'open' => \PrmSecGuard\AlertStore::openCount(),
        ]);
    }
    $result = \PrmSecGuard\GuardEngine::scan(max(10, $interval * 3));
    \PrmSecGuard\Settings::touchCron();

    return response()->json($result + ['cron' => true]);
});

Route::get('/config', function () use ($prmSecGuardLoad) {
    $prmSecGuardLoad();

    return response()->json(\PrmSecGuard\Settings::get());
})->middleware(['auth', AdminAuthenticate::class]);

Route::post('/config', function (Request $request) use ($prmSecGuardLoad) {
    $prmSecGuardLoad();
    $data = $request->all();
    // Light validation — nested rules accepted as arrays.
    if (!is_array($data)) {
        return response()->json(['message' => 'Invalid'], 422);
    }
    $current = \PrmSecGuard\Settings::get();
    if (empty($data['cron_token']) && !empty($current['cron_token'])) {
        $data['cron_token'] = $current['cron_token'];
    }
    if (!empty($data['cron_token_rotate'])) {
        $data['cron_token'] = bin2hex(random_bytes(16));
        unset($data['cron_token_rotate']);
    }
    // Normalize list fields from textarea strings.
    foreach (['ips', 'actor_ids', 'server_ids'] as $k) {
        if (isset($data['allowlist'][$k]) && is_string($data['allowlist'][$k])) {
            $parts = preg_split('/[\s,;]+/', $data['allowlist'][$k]) ?: [];
            $data['allowlist'][$k] = array_values(array_filter(array_map('trim', $parts), static fn ($v) => $v !== ''));
        }
    }
    if (isset($data['allowlist']['actor_ids']) && is_array($data['allowlist']['actor_ids'])) {
        $data['allowlist']['actor_ids'] = array_map('intval', $data['allowlist']['actor_ids']);
    }
    if (isset($data['allowlist']['server_ids']) && is_array($data['allowlist']['server_ids'])) {
        $data['allowlist']['server_ids'] = array_map('intval', $data['allowlist']['server_ids']);
    }
    if (isset($data['mute_rules']) && is_string($data['mute_rules'])) {
        $data['mute_rules'] = array_values(array_filter(array_map('trim', preg_split('/[\s,;]+/', $data['mute_rules']) ?: [])));
    }

    \PrmSecGuard\Settings::put($data);

    return response()->json(['ok' => true, 'config' => \PrmSecGuard\Settings::get()]);
})->middleware(['auth', AdminAuthenticate::class]);

Route::get('/firewall', function (Request $request) use ($prmSecGuardLoad) {
    $prmSecGuardLoad();
    $cfg = \PrmSecGuard\HostFirewall::get();
    $clientIp = (string) $request->ip();

    return response()->json([
        'firewall' => $cfg,
        'client_ip' => $clientIp,
        'catalog' => array_keys(\PrmSecGuard\HostFirewall::serviceCatalog()),
        'export_dir' => \PrmSecGuard\HostFirewall::EXPORT_DIR,
    ]);
})->middleware(['auth', AdminAuthenticate::class]);

Route::post('/firewall', function (Request $request) use ($prmSecGuardLoad) {
    $prmSecGuardLoad();
    $data = $request->all();
    if (!is_array($data)) {
        return response()->json(['message' => 'Invalid'], 422);
    }
    $actor = optional($request->user())->username ?: optional($request->user())->email ?: 'admin';
    // Safety: whitelist/deny on panel without current IP → auto-add client IP.
    if (!empty($data['services']['panel']) && is_array($data['services']['panel'])) {
        $pol = (string) ($data['services']['panel']['policy'] ?? 'allow');
        if (in_array($pol, ['whitelist', 'deny'], true) && !empty($data['services']['panel']['enabled'])) {
            $ip = (string) $request->ip();
            $sources = \PrmSecGuard\HostFirewall::parseSources($data['services']['panel']['sources'] ?? []);
            if ($pol === 'whitelist' && $ip !== '' && !in_array($ip, $sources, true)) {
                $sources[] = $ip;
                $data['services']['panel']['sources'] = $sources;
            }
            if ($pol === 'deny') {
                // App-level deny still allows admin session; host script is drop — warn via flag.
                $data['_panel_deny'] = true;
            }
        }
    }
    $cfg = \PrmSecGuard\HostFirewall::put($data, $actor);

    return response()->json([
        'ok' => true,
        'firewall' => $cfg,
        'panel_deny_warning' => !empty($data['_panel_deny']),
        'client_ip' => (string) $request->ip(),
    ]);
})->middleware(['auth', AdminAuthenticate::class]);

Route::post('/firewall/apply', function (Request $request) use ($prmSecGuardLoad) {
    $prmSecGuardLoad();
    $actor = optional($request->user())->username ?: optional($request->user())->email ?: 'admin';
    $dry = $request->boolean('dry_run', false);

    return response()->json(\PrmSecGuard\HostFirewall::apply($actor, $dry));
})->middleware(['auth', AdminAuthenticate::class]);

Route::post('/firewall/cf-only', function (Request $request) use ($prmSecGuardLoad) {
    $prmSecGuardLoad();
    $extra = [];
    if ($request->boolean('include_me')) {
        $ip = (string) $request->ip();
        if ($ip !== '' && $ip !== '127.0.0.1') {
            $extra[] = $ip;
        }
    }
    $cfg = \PrmSecGuard\HostFirewall::applyCloudflareOnly($extra);
    $actor = optional($request->user())->username ?: optional($request->user())->email ?: 'admin';
    $apply = $request->boolean('apply', false)
        ? \PrmSecGuard\HostFirewall::apply($actor, false)
        : null;

    return response()->json([
        'ok' => true,
        'firewall' => $cfg,
        'cloudflare_cidrs' => count(\PrmSecGuard\HostFirewall::cloudflareIpv4()),
        'apply' => $apply,
        'client_ip' => (string) $request->ip(),
    ]);
})->middleware(['auth', AdminAuthenticate::class]);

Route::get('/firewall/script', function (Request $request) use ($prmSecGuardLoad) {
    $prmSecGuardLoad();
    $cfg = \PrmSecGuard\HostFirewall::get();
    $format = strtolower((string) $request->query('format', $cfg['backend'] ?? 'nftables'));
    if ($format === 'firewalld') {
        $body = \PrmSecGuard\HostFirewall::renderFirewalld($cfg);
        $name = 'host-firewall.firewalld.sh';
        $type = 'text/x-shellscript; charset=UTF-8';
    } else {
        $body = \PrmSecGuard\HostFirewall::renderNftables($cfg);
        $name = 'host-firewall.nft';
        $type = 'text/plain; charset=UTF-8';
    }

    return response($body, 200, [
        'Content-Type' => $type,
        'Content-Disposition' => 'attachment; filename="' . $name . '"',
    ]);
})->middleware(['auth', AdminAuthenticate::class]);

unset($ruleKeys);
