# PRM SecGuard

Blueprint extension: Pterodactyl `activity_logs` üzerinde kural tabanlı güvenlik / anomali uyarıları.

## Version

`1.3.1`

## Hosting / web

Nginx egg siteleri aynı activity stream ile izlenir. Alert `meta.kind` = `hosting` | `game`. Dosya burst eşikleri `file_threshold_scale` (varsayılan 0.75) ile sıkılaşır. Nest/egg boşsa `prmhosting` ayarından alınır.

## Host Firewall

Admin sayfasında **Host Firewall**: Panel / Wings / SFTP / MySQL / HTTP / HTTPS / Site allocation / SSH için allow · deny · whitelist.

- `GET/POST /extensions/prmsecguard/firewall`
- `POST /extensions/prmsecguard/firewall/apply` — script export + panel app senkron (`prmadvanched`)
- `POST /extensions/prmsecguard/firewall/cf-only` — HTTP/HTTPS → sadece Cloudflare IP
- `GET /extensions/prmsecguard/firewall/script?format=nftables|firewalld`
- Export: `extensions/prmsecguard/private/firewall/` (host’ta `nft -f …` veya firewalld script)
- `site_alloc` (8082–8090) varsayılan **deny**; edge localhost kullanır

## Kurallar

| Kural | Ne yakalar |
|-------|------------|
| `mass_delete` / `mass_write` / `mass_download` | Burst dosya işlemleri |
| `backup_burst` | Backup delete/restore |
| `sftp_new_ip` | Yeni IP SFTP (+ gece bump) |
| `api_key_burst` / `api_key_new_burst` | API key patlaması |
| `off_hours_power` | Mesai dışı power |
| `auth_fail_burst` | Login / SFTP fail |
| `subuser_rapid` / `lateral_access` | Subuser / çoklu sunucu |
| `console_burst` | HTTP console komut |
| `console_ws` | Websocket console sampling (dashboard + Next hook) |

**Baseline:** `per_server` açıkken eşik, o sunucunun 7g ortalamasına göre yükselir.

## Fleet / Next

- Admin: `GET /extensions/prmsecguard/report`
- Token: `GET /extensions/prmsecguard/fleet?token=...` (cron token)
- Console sample: `POST /extensions/prmsecguard/console-sample` (session veya token)
- Next: `/secguard` + `SECGUARD_TOKEN`

## Install

```bash
cd /blueprint_extensions/prmsecguard
zip -r ../prmsecguard.blueprint . -x '*.git*'
cp ../prmsecguard.blueprint /app/prmsecguard.blueprint
blueprint -install prmsecguard
```
