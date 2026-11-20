<?php

namespace PrmSecGuard;

use Illuminate\Support\Facades\DB;
use Symfony\Component\HttpFoundation\IpUtils;
use Throwable;

class HostFirewall
{
    public const KEY = 'prmsecguard::firewall';
    public const EXPORT_DIR = '/blueprint_extensions/prmsecguard/private/firewall';

    public static function serviceCatalog(): array
    {
        return [
            'panel' => [
                'label' => 'Panel',
                'ports' => [8080],
                'proto' => 'tcp',
                'enabled' => true,
                'policy' => 'allow',
                'sources' => [],
                'note' => 'Pterodactyl panel (host :8080)',
            ],
            'wings' => [
                'label' => 'Wings',
                'ports' => [8081],
                'proto' => 'tcp',
                'enabled' => true,
                'policy' => 'allow',
                'sources' => [],
                'note' => 'Wings API (host :8081)',
            ],
            'sftp' => [
                'label' => 'SFTP',
                'ports' => [2022],
                'proto' => 'tcp',
                'enabled' => true,
                'policy' => 'allow',
                'sources' => [],
                'note' => 'Wings SFTP',
            ],
            'mysql' => [
                'label' => 'MySQL',
                'ports' => [3307],
                'proto' => 'tcp',
                'enabled' => true,
                'policy' => 'deny',
                'sources' => [],
                'note' => 'MariaDB publish (host :3307) — varsayılan kapalı',
            ],
            'http' => [
                'label' => 'HTTP (edge)',
                'ports' => [80],
                'proto' => 'tcp',
                'enabled' => true,
                'policy' => 'allow',
                'sources' => [],
                'note' => 'Edge nginx — CF-only için policy=whitelist + CF IP',
            ],
            'https' => [
                'label' => 'HTTPS (edge)',
                'ports' => [443],
                'proto' => 'tcp',
                'enabled' => true,
                'policy' => 'allow',
                'sources' => [],
                'note' => 'Edge TLS — CF-only için policy=whitelist + CF IP',
            ],
            'site_alloc' => [
                'label' => 'Site allocation',
                'ports' => [8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090],
                'proto' => 'tcp',
                'enabled' => true,
                'policy' => 'deny',
                'sources' => [],
                'note' => 'Wings site portları — WAN kapalı (edge localhost kullanır)',
            ],
            'ssh' => [
                'label' => 'SSH',
                'ports' => [22],
                'proto' => 'tcp',
                'enabled' => false,
                'policy' => 'whitelist',
                'sources' => [],
                'note' => 'Host SSH — dikkatli kullan',
            ],
        ];
    }

    /** Cloudflare published IPv4 ranges (update periodically). */
    public static function cloudflareIpv4(): array
    {
        return [
            '173.245.48.0/20',
            '103.21.244.0/22',
            '103.22.200.0/22',
            '103.31.4.0/22',
            '141.101.64.0/18',
            '108.162.192.0/18',
            '190.93.240.0/20',
            '188.114.96.0/20',
            '197.234.240.0/22',
            '198.41.128.0/17',
            '162.158.0.0/15',
            '104.16.0.0/13',
            '104.24.0.0/14',
            '172.64.0.0/13',
            '131.0.72.0/22',
        ];
    }

    /**
     * HTTP/HTTPS → whitelist only Cloudflare (and optional extra sources).
     *
     * @param list<string> $extra
     */
    public static function applyCloudflareOnly(array $extra = []): array
    {
        $cfg = self::get();
        $sources = array_values(array_unique(array_merge(self::cloudflareIpv4(), $extra)));
        foreach (['http', 'https'] as $id) {
            if (!isset($cfg['services'][$id])) {
                continue;
            }
            $cfg['services'][$id]['enabled'] = true;
            $cfg['services'][$id]['policy'] = 'whitelist';
            $cfg['services'][$id]['sources'] = $sources;
            $cfg['services'][$id]['note'] = 'CF-only origin (Cloudflare IP whitelist)';
        }
        self::put($cfg);

        return self::get();
    }

    public static function defaults(): array
    {
        return [
            'enabled' => true,
            'backend' => 'nftables',
            'sync_panel_app' => true,
            'last_applied_at' => 0,
            'last_apply_status' => '',
            'last_apply_detail' => '',
            'services' => self::serviceCatalog(),
            'audit' => [],
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
            $out = array_merge($defaults, $parsed);
            $catalog = self::serviceCatalog();
            $services = [];
            foreach ($catalog as $id => $base) {
                $over = is_array($parsed['services'][$id] ?? null) ? $parsed['services'][$id] : [];
                $services[$id] = self::normalizeService($id, array_merge($base, $over));
            }
            // Keep any custom extras (rare).
            if (is_array($parsed['services'] ?? null)) {
                foreach ($parsed['services'] as $id => $svc) {
                    if (isset($services[$id]) || !is_array($svc)) {
                        continue;
                    }
                    $services[$id] = self::normalizeService((string) $id, $svc);
                }
            }
            $out['services'] = $services;
            $out['audit'] = is_array($out['audit'] ?? null) ? array_slice($out['audit'], 0, 80) : [];
            $out['backend'] = in_array($out['backend'] ?? '', ['nftables', 'firewalld'], true)
                ? $out['backend']
                : 'nftables';

            return $out;
        } catch (Throwable $e) {
            return $defaults;
        }
    }

    public static function put(array $config, string $actor = 'admin'): array
    {
        $current = self::get();
        $merged = array_merge($current, $config);
        $catalog = self::serviceCatalog();
        $services = [];
        $incoming = is_array($config['services'] ?? null) ? $config['services'] : ($current['services'] ?? []);
        foreach ($catalog as $id => $base) {
            $over = is_array($incoming[$id] ?? null) ? $incoming[$id] : ($current['services'][$id] ?? $base);
            $services[$id] = self::normalizeService($id, array_merge($base, $over));
        }
        $merged['services'] = $services;
        $merged['enabled'] = !empty($merged['enabled']);
        $merged['sync_panel_app'] = array_key_exists('sync_panel_app', $config)
            ? !empty($config['sync_panel_app'])
            : !empty($current['sync_panel_app']);
        $merged['backend'] = in_array($merged['backend'] ?? '', ['nftables', 'firewalld'], true)
            ? $merged['backend']
            : 'nftables';
        $merged['audit'] = is_array($current['audit'] ?? null) ? $current['audit'] : [];

        DB::table('settings')->updateOrInsert(
            ['key' => self::KEY],
            ['value' => serialize($merged)]
        );

        self::audit($merged, 'save', $actor, 'Kurallar kaydedildi');

        if (!empty($merged['sync_panel_app'])) {
            self::syncPanelAppFirewall($merged);
        }

        return self::get();
    }

    public static function normalizeIp(string $raw): ?string
    {
        $raw = trim($raw);
        if ($raw === '') {
            return null;
        }
        if (strpos($raw, '/') !== false) {
            [$net, $bits] = array_pad(explode('/', $raw, 2), 2, '');
            $net = trim($net);
            $bits = (int) $bits;
            if (filter_var($net, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                return ($bits >= 8 && $bits <= 32) ? ($net . '/' . $bits) : null;
            }
            if (filter_var($net, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                return ($bits >= 32 && $bits <= 128) ? ($net . '/' . $bits) : null;
            }

            return null;
        }
        $ip = filter_var($raw, FILTER_VALIDATE_IP);

        return $ip !== false ? $ip : null;
    }

    public static function parseSources($raw): array
    {
        if (is_array($raw)) {
            $parts = $raw;
        } else {
            $parts = preg_split('/[\s,;]+/', (string) $raw) ?: [];
        }
        $out = [];
        foreach ($parts as $p) {
            $n = self::normalizeIp((string) $p);
            if ($n !== null) {
                $out[$n] = $n;
            }
        }

        return array_values($out);
    }

    private static function normalizeService(string $id, array $svc): array
    {
        $policy = strtolower((string) ($svc['policy'] ?? 'allow'));
        if (!in_array($policy, ['allow', 'deny', 'whitelist'], true)) {
            $policy = 'allow';
        }
        $ports = [];
        $rawPorts = $svc['ports'] ?? [];
        if (is_string($rawPorts)) {
            $rawPorts = preg_split('/[\s,;]+/', $rawPorts) ?: [];
        }
        if (!is_array($rawPorts)) {
            $rawPorts = [];
        }
        foreach ($rawPorts as $p) {
            $n = (int) $p;
            if ($n >= 1 && $n <= 65535) {
                $ports[$n] = $n;
            }
        }
        $ports = array_values($ports);
        if ($ports === [] && isset(self::serviceCatalog()[$id])) {
            $ports = self::serviceCatalog()[$id]['ports'];
        }
        $proto = strtolower((string) ($svc['proto'] ?? 'tcp'));
        if (!in_array($proto, ['tcp', 'udp'], true)) {
            $proto = 'tcp';
        }

        return [
            'label' => (string) ($svc['label'] ?? $id),
            'ports' => $ports,
            'proto' => $proto,
            'enabled' => !empty($svc['enabled']),
            'policy' => $policy,
            'sources' => self::parseSources($svc['sources'] ?? []),
            'note' => mb_substr((string) ($svc['note'] ?? ''), 0, 200),
        ];
    }

    public static function audit(array &$cfg, string $action, string $actor, string $detail): void
    {
        $entry = [
            'ts' => time(),
            'action' => $action,
            'actor' => mb_substr($actor, 0, 80),
            'detail' => mb_substr($detail, 0, 240),
        ];
        $list = is_array($cfg['audit'] ?? null) ? $cfg['audit'] : [];
        array_unshift($list, $entry);
        $cfg['audit'] = array_slice($list, 0, 80);
        try {
            DB::table('settings')->updateOrInsert(
                ['key' => self::KEY],
                ['value' => serialize($cfg)]
            );
        } catch (Throwable $e) {
            // ignore
        }
    }

    public static function syncPanelAppFirewall(array $cfg): array
    {
        $result = ['ok' => false, 'detail' => 'prmadvanched yok'];
        $path = '/blueprint_extensions/prmadvanched/lib/Firewall.php';
        if (!class_exists('PrmAdvanchedFirewall', false) && is_file($path)) {
            require_once $path;
        }
        if (!class_exists('PrmAdvanchedFirewall', false)) {
            return $result;
        }
        try {
            $panel = $cfg['services']['panel'] ?? null;
            if (!is_array($panel) || empty($panel['enabled']) || empty($cfg['enabled'])) {
                \PrmAdvanchedFirewall::write('firewall_panel_whitelist', '0');

                return ['ok' => true, 'detail' => 'panel app whitelist kapalı'];
            }
            $policy = $panel['policy'] ?? 'allow';
            if ($policy === 'whitelist') {
                \PrmAdvanchedFirewall::write('firewall_panel_whitelist', '1');
                $rows = [];
                foreach ($panel['sources'] as $ip) {
                    $rows[] = [
                        'ip' => $ip,
                        'note' => 'SecGuard host firewall',
                        'source' => 'secguard',
                        'at' => time(),
                    ];
                }
                \PrmAdvanchedFirewall::write('firewall_panel_allow', $rows);
                \PrmAdvanchedFirewall::write('firewall_enabled', '1');

                return ['ok' => true, 'detail' => 'panel whitelist senkron (' . count($rows) . ' IP)'];
            }
            if ($policy === 'deny') {
                \PrmAdvanchedFirewall::write('firewall_panel_whitelist', '1');
                \PrmAdvanchedFirewall::write('firewall_panel_allow', []);
                \PrmAdvanchedFirewall::write('firewall_enabled', '1');

                return ['ok' => true, 'detail' => 'panel deny (app-level, admin oturum muaf)'];
            }
            \PrmAdvanchedFirewall::write('firewall_panel_whitelist', '0');

            return ['ok' => true, 'detail' => 'panel allow (whitelist off)'];
        } catch (Throwable $e) {
            return ['ok' => false, 'detail' => $e->getMessage()];
        }
    }

    public static function renderNftables(array $cfg): string
    {
        $lines = [
            '# Generated by PRM SecGuard Host Firewall',
            '# Apply on HOST (not inside panel container):',
            '#   nft -f ' . self::EXPORT_DIR . '/host-firewall.nft',
            '',
            'table inet peto_secguard {',
            '  chain input {',
            '    type filter hook input priority 0; policy accept;',
            '    ct state established,related accept',
            '    iif lo accept',
        ];
        if (empty($cfg['enabled'])) {
            $lines[] = '    # SecGuard host firewall disabled — passthrough';
            $lines[] = '  }';
            $lines[] = '}';

            return implode("\n", $lines) . "\n";
        }
        foreach ($cfg['services'] as $id => $svc) {
            if (empty($svc['enabled']) || empty($svc['ports'])) {
                continue;
            }
            $proto = $svc['proto'] === 'udp' ? 'udp' : 'tcp';
            $ports = implode(', ', $svc['ports']);
            $lines[] = '    # ' . $svc['label'] . ' (' . $id . ') policy=' . $svc['policy'];
            if ($svc['policy'] === 'allow') {
                $lines[] = '    ' . $proto . ' dport { ' . $ports . ' } accept';
                continue;
            }
            if ($svc['policy'] === 'deny') {
                $lines[] = '    ' . $proto . ' dport { ' . $ports . ' } drop';
                continue;
            }
            // whitelist
            if ($svc['sources'] === []) {
                $lines[] = '    ' . $proto . ' dport { ' . $ports . ' } drop';
                continue;
            }
            foreach ($svc['sources'] as $src) {
                $lines[] = '    ip saddr ' . $src . ' ' . $proto . ' dport { ' . $ports . ' } accept';
            }
            $lines[] = '    ' . $proto . ' dport { ' . $ports . ' } drop';
        }
        $lines[] = '  }';
        $lines[] = '}';

        return implode("\n", $lines) . "\n";
    }

    public static function renderFirewalld(array $cfg): string
    {
        $lines = [
            '#!/bin/bash',
            '# Generated by PRM SecGuard Host Firewall',
            '# Run on HOST as root:',
            '#   bash ' . self::EXPORT_DIR . '/host-firewall.firewalld.sh',
            'set -euo pipefail',
            'command -v firewall-cmd >/dev/null || { echo "firewall-cmd yok"; exit 1; }',
            'ZONE="${FIREWALLD_ZONE:-public}"',
        ];
        if (empty($cfg['enabled'])) {
            $lines[] = 'echo "SecGuard host firewall disabled — no changes"';
            $lines[] = 'exit 0';

            return implode("\n", $lines) . "\n";
        }
        foreach ($cfg['services'] as $id => $svc) {
            if (empty($svc['enabled']) || empty($svc['ports'])) {
                continue;
            }
            $proto = $svc['proto'] === 'udp' ? 'udp' : 'tcp';
            $lines[] = "echo '# {$svc['label']} ({$id}) policy={$svc['policy']}'";
            foreach ($svc['ports'] as $port) {
                $portProto = $port . '/' . $proto;
                if ($svc['policy'] === 'allow') {
                    $lines[] = "firewall-cmd --permanent --zone=\"\$ZONE\" --add-port={$portProto} || true";
                    continue;
                }
                if ($svc['policy'] === 'deny') {
                    $lines[] = "firewall-cmd --permanent --zone=\"\$ZONE\" --remove-port={$portProto} || true";
                    $lines[] = "firewall-cmd --permanent --zone=\"\$ZONE\" --remove-rich-rule=\"rule family=ipv4 port port={$port} protocol={$proto} accept\" 2>/dev/null || true";
                    continue;
                }
                $lines[] = "firewall-cmd --permanent --zone=\"\$ZONE\" --remove-port={$portProto} || true";
                foreach ($svc['sources'] as $src) {
                    $lines[] = "firewall-cmd --permanent --zone=\"\$ZONE\" --add-rich-rule=\"rule family=ipv4 source address={$src} port port={$port} protocol={$proto} accept\"";
                }
            }
        }
        $lines[] = 'firewall-cmd --reload';
        $lines[] = 'echo "OK"';

        return implode("\n", $lines) . "\n";
    }

    public static function exportScripts(array $cfg): array
    {
        $dir = self::EXPORT_DIR;
        if (!is_dir($dir) && !@mkdir($dir, 0755, true) && !is_dir($dir)) {
            throw new \RuntimeException('Export dizini oluşturulamadı: ' . $dir);
        }
        $nft = self::renderNftables($cfg);
        $fwd = self::renderFirewalld($cfg);
        $json = json_encode([
            'generated_at' => time(),
            'backend' => $cfg['backend'] ?? 'nftables',
            'enabled' => !empty($cfg['enabled']),
            'services' => $cfg['services'] ?? [],
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        file_put_contents($dir . '/host-firewall.nft', $nft);
        file_put_contents($dir . '/host-firewall.firewalld.sh', $fwd);
        @chmod($dir . '/host-firewall.firewalld.sh', 0755);
        file_put_contents($dir . '/host-firewall.json', $json . "\n");

        return [
            'dir' => $dir,
            'nft' => $dir . '/host-firewall.nft',
            'firewalld' => $dir . '/host-firewall.firewalld.sh',
            'json' => $dir . '/host-firewall.json',
        ];
    }

    public static function apply(string $actor = 'admin', bool $dryRun = false): array
    {
        $cfg = self::get();
        $paths = self::exportScripts($cfg);
        $sync = ['ok' => false, 'detail' => 'skipped'];
        if (!empty($cfg['sync_panel_app'])) {
            $sync = self::syncPanelAppFirewall($cfg);
        }

        $hostApply = [
            'attempted' => false,
            'ok' => false,
            'detail' => 'Panel container içinde host nft/firewalld yok; script host\'ta uygulanmalı',
        ];
        $backend = $cfg['backend'] ?? 'nftables';
        if (!$dryRun) {
            if ($backend === 'nftables' && is_executable('/usr/sbin/nft')) {
                $hostApply['attempted'] = true;
                $cmd = 'nft -c -f ' . escapeshellarg($paths['nft']) . ' 2>&1';
                $out = [];
                $code = 0;
                @exec($cmd, $out, $code);
                if ($code === 0) {
                    @exec('nft -f ' . escapeshellarg($paths['nft']) . ' 2>&1', $out2, $code2);
                    $hostApply['ok'] = $code2 === 0;
                    $hostApply['detail'] = $hostApply['ok']
                        ? 'nftables uygulandı'
                        : ('nft apply hata: ' . implode(' ', $out2 ?? []));
                } else {
                    $hostApply['detail'] = 'nft dry-check hata: ' . implode(' ', $out);
                }
            } elseif ($backend === 'firewalld' && is_executable('/usr/bin/firewall-cmd')) {
                $hostApply['attempted'] = true;
                @exec('bash ' . escapeshellarg($paths['firewalld']) . ' 2>&1', $out, $code);
                $hostApply['ok'] = $code === 0;
                $hostApply['detail'] = $hostApply['ok']
                    ? 'firewalld uygulandı'
                    : ('firewalld hata: ' . implode(' ', $out ?? []));
            }
        }

        $status = $dryRun ? 'dry_run' : 'exported';
        $detail = 'Script yazıldı: ' . $paths['dir'];
        if (!empty($sync['ok'])) {
            $detail .= ' · ' . $sync['detail'];
        }
        if ($hostApply['attempted']) {
            $status = $hostApply['ok'] ? 'applied_host' : 'export_host_failed';
            $detail .= ' · ' . $hostApply['detail'];
        } else {
            $detail .= ' · ' . $hostApply['detail'];
        }

        $cfg['last_applied_at'] = time();
        $cfg['last_apply_status'] = $status;
        $cfg['last_apply_detail'] = $detail;
        self::audit($cfg, $dryRun ? 'dry_run' : 'apply', $actor, $detail);

        return [
            'ok' => true,
            'status' => $status,
            'detail' => $detail,
            'paths' => $paths,
            'sync_panel' => $sync,
            'host' => $hostApply,
            'script_nft' => file_get_contents($paths['nft']) ?: '',
            'config' => self::get(),
        ];
    }

    public static function ensureSourceHasIp(array $cfg, string $serviceId, string $ip): array
    {
        $ip = self::normalizeIp($ip);
        if ($ip === null || !isset($cfg['services'][$serviceId])) {
            return $cfg;
        }
        $sources = $cfg['services'][$serviceId]['sources'] ?? [];
        if (!in_array($ip, $sources, true)) {
            $sources[] = $ip;
            $cfg['services'][$serviceId]['sources'] = $sources;
        }

        return $cfg;
    }

    public static function ipAllowedPreview(string $ip, array $svc): bool
    {
        if (empty($svc['enabled'])) {
            return true;
        }
        $policy = $svc['policy'] ?? 'allow';
        if ($policy === 'allow') {
            return true;
        }
        if ($policy === 'deny') {
            return false;
        }
        foreach ($svc['sources'] as $rule) {
            try {
                if (IpUtils::checkIp($ip, $rule)) {
                    return true;
                }
            } catch (Throwable $e) {
                if (strcasecmp($ip, $rule) === 0) {
                    return true;
                }
            }
        }

        return false;
    }
}
