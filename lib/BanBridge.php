<?php

namespace PrmSecGuard;

use Throwable;

class BanBridge
{
    public static function load(): bool
    {
        if (class_exists('PrmAdvanchedFirewall', false)) {
            return true;
        }
        $path = '/blueprint_extensions/prmadvanched/lib/Firewall.php';
        if (is_file($path)) {
            require_once $path;
        }

        return class_exists('PrmAdvanchedFirewall', false);
    }

    public static function available(): bool
    {
        return self::load();
    }

    public static function ban(string $ip, string $note = ''): array
    {
        if (!self::load()) {
            return ['ok' => false, 'error' => 'prmadvanched firewall yok'];
        }
        try {
            $bans = \PrmAdvanchedFirewall::addBan($ip, $note !== '' ? $note : 'SecGuard', 'auto');

            return ['ok' => true, 'bans' => $bans];
        } catch (Throwable $e) {
            return ['ok' => false, 'error' => $e->getMessage()];
        }
    }

    public static function isBanned(string $ip): bool
    {
        if (!self::load() || $ip === '') {
            return false;
        }
        try {
            return \PrmAdvanchedFirewall::isBanned($ip);
        } catch (Throwable $e) {
            return false;
        }
    }
}
