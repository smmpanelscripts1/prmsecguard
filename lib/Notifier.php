<?php

namespace PrmSecGuard;

use Throwable;

class Notifier
{
    private static array $rank = [
        'low' => 1,
        'medium' => 2,
        'high' => 3,
        'critical' => 4,
    ];

    public static function send(array $alert, array $cfg): void
    {
        $notify = $cfg['notify'] ?? [];
        if (empty($notify['enabled'])) {
            return;
        }

        $min = (string) ($notify['min_severity'] ?? 'high');
        $sev = (string) ($alert['severity'] ?? 'medium');
        if ((self::$rank[$sev] ?? 0) < (self::$rank[$min] ?? 3)) {
            return;
        }

        $title = (string) ($alert['title'] ?? 'SecGuard');
        $detail = (string) ($alert['detail'] ?? '');
        $line = sprintf(
            "[SecGuard/%s] %s — %s (rule=%s ip=%s actor=%s server=%s)",
            strtoupper($sev),
            $title,
            $detail,
            $alert['rule'] ?? '',
            $alert['ip'] ?? '',
            $alert['actor_id'] ?? '-',
            $alert['server_id'] ?? '-'
        );

        $webhook = trim((string) ($notify['webhook_url'] ?? ''));
        if ($webhook !== '') {
            self::postJson($webhook, ['text' => $line, 'content' => $line, 'alert' => $alert]);
        }

        $discord = trim((string) ($notify['discord_webhook'] ?? ''));
        if ($discord !== '') {
            $color = match ($sev) {
                'critical' => 15158332,
                'high' => 15105570,
                'medium' => 15844367,
                default => 3447003,
            };
            self::postJson($discord, [
                'embeds' => [[
                    'title' => 'SecGuard: ' . $title,
                    'description' => $detail,
                    'color' => $color,
                    'fields' => [
                        ['name' => 'Rule', 'value' => (string) ($alert['rule'] ?? '-'), 'inline' => true],
                        ['name' => 'Severity', 'value' => $sev, 'inline' => true],
                        ['name' => 'IP', 'value' => (string) ($alert['ip'] ?: '-'), 'inline' => true],
                        ['name' => 'Actor', 'value' => (string) ($alert['actor_id'] ?: '-'), 'inline' => true],
                        ['name' => 'Server', 'value' => (string) ($alert['server_id'] ?: '-'), 'inline' => true],
                    ],
                    'timestamp' => gmdate('c', (int) ($alert['ts'] ?? time())),
                ]],
            ]);
        }

        $bot = trim((string) ($notify['telegram_bot_token'] ?? ''));
        $chat = trim((string) ($notify['telegram_chat_id'] ?? ''));
        if ($bot !== '' && $chat !== '') {
            self::postForm('https://api.telegram.org/bot' . rawurlencode($bot) . '/sendMessage', [
                'chat_id' => $chat,
                'text' => $line,
                'disable_web_page_preview' => '1',
            ]);
        }
    }

    private static function postJson(string $url, array $payload): void
    {
        try {
            $ctx = stream_context_create([
                'http' => [
                    'method' => 'POST',
                    'header' => "Content-Type: application/json\r\nAccept: application/json\r\n",
                    'content' => json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
                    'timeout' => 4,
                    'ignore_errors' => true,
                ],
            ]);
            @file_get_contents($url, false, $ctx);
        } catch (Throwable $e) {
            // best-effort
        }
    }

    private static function postForm(string $url, array $fields): void
    {
        try {
            $ctx = stream_context_create([
                'http' => [
                    'method' => 'POST',
                    'header' => "Content-Type: application/x-www-form-urlencoded\r\n",
                    'content' => http_build_query($fields),
                    'timeout' => 4,
                    'ignore_errors' => true,
                ],
            ]);
            @file_get_contents($url, false, $ctx);
        } catch (Throwable $e) {
            // best-effort
        }
    }
}
