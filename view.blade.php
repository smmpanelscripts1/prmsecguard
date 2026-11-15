<link rel="stylesheet" href="/assets/extensions/prmsecguard/admin.style.css?v=1.2.1">

<div class="prmsec-wrap">
  <div class="row">
    <div class="col-xs-12">
      <div class="box box-danger">
        <div class="box-header with-border">
          <h3 class="box-title">Uyarılar</h3>
          <div class="box-tools pull-right">
            <span class="prmsec-muted" id="prmsec-updated">—</span>
          </div>
        </div>
        <div class="box-body">
          <div class="prmsec-kpi-row">
            <div class="prmsec-kpi is-open"><p class="prmsec-kpi__label">Açık uyarı</p><p class="prmsec-kpi__value" id="prmsec-open">0</p></div>
            <div class="prmsec-kpi is-ok"><p class="prmsec-kpi__label">Durum</p><p class="prmsec-kpi__value" id="prmsec-enabled">—</p></div>
            <div class="prmsec-kpi is-scan"><p class="prmsec-kpi__label">Son tarama</p><p class="prmsec-kpi__value" id="prmsec-scan-meta">—</p></div>
            <div class="prmsec-kpi is-rules"><p class="prmsec-kpi__label">Kurallar</p><p class="prmsec-kpi__value" id="prmsec-rules-on">—</p></div>
          </div>

          <div class="prmsec-toolbar">
            <button type="button" class="btn btn-primary btn-sm" id="prmsec-scan">Son 60 dk tara</button>
            <button type="button" class="btn btn-default btn-sm" id="prmsec-refresh">Yenile</button>
            <button type="button" class="btn btn-warning btn-sm" id="prmsec-ack-all">Tümünü onayla</button>
            <a class="btn btn-default btn-sm" id="prmsec-csv" href="/extensions/prmsecguard/alerts.csv?open=1">CSV</a>
            <label><input type="checkbox" id="prmsec-open-only" checked> Sadece açık</label>
            <select id="prmsec-filter-sev" class="form-control input-sm" style="width:120px;display:inline-block">
              <option value="">Seviye</option>
              <option value="critical">critical</option>
              <option value="high">high</option>
              <option value="medium">medium</option>
              <option value="low">low</option>
            </select>
            <select id="prmsec-filter-rule" class="form-control input-sm" style="width:160px;display:inline-block">
              <option value="">Kural</option>
            </select>
            <input type="search" id="prmsec-filter-q" class="form-control input-sm" placeholder="Ara…" style="width:140px;display:inline-block">
          </div>

          <div class="prmsec-split">
            <div class="table-responsive">
              <table class="table table-striped table-hover prmsec-table" id="prmsec-table">
                <thead>
                  <tr>
                    <th style="width:150px">Zaman</th>
                    <th style="width:80px">Seviye</th>
                    <th style="width:130px">Kural</th>
                    <th>Özet</th>
                    <th style="width:150px">Aktör / IP</th>
                    <th style="width:140px"></th>
                  </tr>
                </thead>
                <tbody></tbody>
              </table>
              <p class="prmsec-muted" id="prmsec-empty" style="display:none">Uyarı yok.</p>
            </div>
            <div class="prmsec-context" id="prmsec-context">
              <h4>Aktivite özeti</h4>
              <p class="prmsec-muted" id="prmsec-context-empty">Bir uyarıdan “Detay” seç.</p>
              <ul id="prmsec-context-list"></ul>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <div class="row">
    <div class="col-xs-12">
      <div class="box box-primary">
        <div class="box-header with-border"><h3 class="box-title">Ayarlar</h3></div>
        <div class="box-body" id="prmsec-settings">
          <div class="prmsec-master">
            <label><input type="checkbox" id="cfg-enabled"> SecGuard aktif</label>
          </div>

          <div class="prmsec-rules" id="prmsec-rule-cards"></div>

          <div class="prmsec-rule" style="margin-top:12px">
            <div class="prmsec-rule__head"><h4>Bildirimler</h4></div>
            <label class="prmsec-rule__toggle"><input type="checkbox" id="cfg-notify-en"> Aktif</label>
            <div class="prmsec-fields" style="margin-top:10px">
              <div class="prmsec-field"><label>Min severity</label>
                <select class="form-control" id="cfg-notify-min">
                  <option value="critical">critical</option>
                  <option value="high">high</option>
                  <option value="medium">medium</option>
                </select>
              </div>
              <div class="prmsec-field"><label>Webhook URL</label><input class="form-control" type="text" id="cfg-notify-hook"></div>
              <div class="prmsec-field"><label>Discord webhook</label><input class="form-control" type="text" id="cfg-notify-discord"></div>
              <div class="prmsec-field"><label>Telegram bot token</label><input class="form-control" type="text" id="cfg-notify-tg-token"></div>
              <div class="prmsec-field"><label>Telegram chat id</label><input class="form-control" type="text" id="cfg-notify-tg-chat"></div>
              <div class="prmsec-field"><label>&nbsp;</label>
                <label class="prmsec-rule__toggle"><input type="checkbox" id="cfg-notify-autoban"> Auth fail → auto-ban (prmadvanched)</label>
              </div>
            </div>
          </div>

          <div class="prmsec-rule" style="margin-top:12px">
            <div class="prmsec-rule__head"><h4>Allowlist / Mute / Cron</h4></div>
            <div class="prmsec-fields">
              <div class="prmsec-field" style="grid-column:1/-1"><label>Allow IP (virgül)</label><input class="form-control" type="text" id="cfg-al-ips"></div>
              <div class="prmsec-field"><label>Allow actor id</label><input class="form-control" type="text" id="cfg-al-actors"></div>
              <div class="prmsec-field"><label>Allow server id</label><input class="form-control" type="text" id="cfg-al-servers"></div>
              <div class="prmsec-field" style="grid-column:1/-1"><label>Mute rules (virgül)</label><input class="form-control" type="text" id="cfg-mute"></div>
              <div class="prmsec-field"><label>Retention (gün)</label><input class="form-control" type="number" id="cfg-retention" min="1" max="365"></div>
              <div class="prmsec-field"><label>Cron interval (dk)</label><input class="form-control" type="number" id="cfg-cron-int" min="1" max="1440"></div>
              <div class="prmsec-field" style="grid-column:1/-1"><label>Cron URL</label>
                <input class="form-control" type="text" id="cfg-cron-url" readonly>
                <button type="button" class="btn btn-xs btn-default" id="cfg-cron-rotate" style="margin-top:6px">Token üret / yenile</button>
              </div>
              <div class="prmsec-field"><label>Baseline</label>
                <label class="prmsec-rule__toggle"><input type="checkbox" id="cfg-baseline-en"> Dinamik eşik</label>
              </div>
              <div class="prmsec-field"><label>Sunucu bazlı</label>
                <label class="prmsec-rule__toggle"><input type="checkbox" id="cfg-baseline-server"> Per-server</label>
              </div>
              <div class="prmsec-field"><label>Baseline çarpan</label><input class="form-control" type="number" step="0.1" id="cfg-baseline-mult" min="1" max="20"></div>
            </div>
          </div>

          <div class="prmsec-actions">
            <button type="button" class="btn btn-success" id="prmsec-save">Kaydet</button>
            <div class="prmsec-msg" id="prmsec-save-msg"></div>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>

<script>
(function () {
  function csrf() {
    const m = document.querySelector('meta[name="csrf-token"], meta[name="_token"]');
    if (m && m.content) return m.content;
    const input = document.querySelector('input[name="_token"]');
    return input ? input.value : '';
  }
  const base = '/extensions/prmsecguard';
  const tbody = document.querySelector('#prmsec-table tbody');
  const empty = document.getElementById('prmsec-empty');
  let cfgCache = {};
  let banAvailable = false;

  const RULES = [
    { key: 'mass_delete', title: 'Toplu silme', fields: [['threshold','Eşik'],['window_sec','Pencere (sn)']] },
    { key: 'mass_write', title: 'Toplu yazma', fields: [['threshold','Eşik'],['window_sec','Pencere (sn)']] },
    { key: 'mass_download', title: 'Toplu indirme', fields: [['threshold','Eşik'],['window_sec','Pencere (sn)']] },
    { key: 'backup_burst', title: 'Backup burst', fields: [['threshold','Eşik'],['window_sec','Pencere (sn)']] },
    { key: 'sftp_new_ip', title: 'Yeni SFTP IP', fields: [['lookback_days','Lookback (gün)']] },
    { key: 'sftp_night_new_ip', title: 'Gece SFTP bump', fields: [['start_hour','Başlangıç'],['end_hour','Bitiş'],['timezone','Timezone']] },
    { key: 'api_key_burst', title: 'API key burst', fields: [['threshold','Eşik'],['window_sec','Pencere (sn)']] },
    { key: 'api_key_new_burst', title: 'Yeni API key burst', fields: [['age_sec','Key yaşı (sn)'],['threshold','Eşik'],['window_sec','Pencere (sn)']] },
    { key: 'off_hours_power', title: 'Mesai dışı power', fields: [['start_hour','Başlangıç'],['end_hour','Bitiş'],['timezone','Timezone']] },
    { key: 'auth_fail_burst', title: 'Auth fail burst', fields: [['threshold','Eşik'],['window_sec','Pencere (sn)']] },
    { key: 'subuser_rapid', title: 'Subuser rapid', fields: [['window_sec','Pencere (sn)'],['action_threshold','Aksiyon eşik']] },
    { key: 'lateral_access', title: 'Lateral erişim', fields: [['server_threshold','Sunucu eşik'],['window_sec','Pencere (sn)']] },
    { key: 'console_burst', title: 'Console burst (HTTP)', fields: [['threshold','Eşik'],['window_sec','Pencere (sn)']] },
    { key: 'console_ws', title: 'Console WS sampling', fields: [['threshold','Eşik'],['window_sec','Pencere (sn)']] },
  ];

  const ruleLabel = Object.fromEntries(RULES.map(r => [r.key, r.title]));
  ruleLabel.sftp_new_ip = 'Yeni SFTP IP';

  function esc(s) {
    return String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }
  function fmtTs(ts) {
    try { return new Date(ts * 1000).toLocaleString(); } catch (e) { return String(ts); }
  }
  async function api(path, opts) {
    const token = csrf();
    const headers = {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
      'X-CSRF-TOKEN': token,
      'X-XSRF-TOKEN': token,
      'X-Requested-With': 'XMLHttpRequest',
    };
    const init = Object.assign({ credentials: 'same-origin', headers }, opts || {});
    if (init.body && typeof init.body === 'string' && token) {
      try {
        const parsed = JSON.parse(init.body);
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed) && !parsed._token) {
          parsed._token = token;
          init.body = JSON.stringify(parsed);
        }
      } catch (e) {}
    }
    const res = await fetch(base + path, init);
    const text = await res.text();
    let json = null; try { json = JSON.parse(text); } catch (e) {}
    if (!res.ok) throw new Error((json && (json.message || json.error)) || ('HTTP ' + res.status));
    return json;
  }

  function buildRuleCards() {
    const host = document.getElementById('prmsec-rule-cards');
    host.innerHTML = RULES.map(r => {
      const fields = r.fields.map(([k, lab]) =>
        `<div class="prmsec-field"><label>${esc(lab)}</label><input class="form-control" data-rule="${r.key}" data-field="${k}" type="text"></div>`
      ).join('');
      return `<div class="prmsec-rule" data-rule-card="${r.key}">
        <div class="prmsec-rule__head"><h4>${esc(r.title)}</h4>
          <label class="prmsec-rule__toggle"><input type="checkbox" data-rule-en="${r.key}"> Aktif</label>
        </div>
        <div class="prmsec-fields">${fields}</div>
      </div>`;
    }).join('');

    const sel = document.getElementById('prmsec-filter-rule');
    sel.innerHTML = '<option value="">Kural</option>' + RULES.map(r =>
      `<option value="${r.key}">${esc(r.title)}</option>`).join('');
  }

  function fillConfig(cfg) {
    cfgCache = cfg;
    banAvailable = !!cfg._ban;
    document.getElementById('cfg-enabled').checked = !!cfg.enabled;
    RULES.forEach(r => {
      const block = cfg[r.key] || {};
      const en = document.querySelector(`[data-rule-en="${r.key}"]`);
      if (en) en.checked = !!block.enabled;
      r.fields.forEach(([k]) => {
        const input = document.querySelector(`[data-rule="${r.key}"][data-field="${k}"]`);
        if (input) input.value = block[k] ?? '';
      });
    });
    const n = cfg.notify || {};
    document.getElementById('cfg-notify-en').checked = !!n.enabled;
    document.getElementById('cfg-notify-min').value = n.min_severity || 'high';
    document.getElementById('cfg-notify-hook').value = n.webhook_url || '';
    document.getElementById('cfg-notify-discord').value = n.discord_webhook || '';
    document.getElementById('cfg-notify-tg-token').value = n.telegram_bot_token || '';
    document.getElementById('cfg-notify-tg-chat').value = n.telegram_chat_id || '';
    document.getElementById('cfg-notify-autoban').checked = !!n.auto_ban_auth_fail;
    const al = cfg.allowlist || {};
    document.getElementById('cfg-al-ips').value = (al.ips || []).join(', ');
    document.getElementById('cfg-al-actors').value = (al.actor_ids || []).join(', ');
    document.getElementById('cfg-al-servers').value = (al.server_ids || []).join(', ');
    document.getElementById('cfg-mute').value = (cfg.mute_rules || []).join(', ');
    document.getElementById('cfg-retention').value = cfg.retention_days ?? 30;
    document.getElementById('cfg-cron-int').value = cfg.cron_interval_min ?? 5;
    document.getElementById('cfg-baseline-en').checked = !!(cfg.baseline && cfg.baseline.enabled);
    document.getElementById('cfg-baseline-server').checked = !!(cfg.baseline && cfg.baseline.per_server !== false);
    document.getElementById('cfg-baseline-mult').value = (cfg.baseline && cfg.baseline.multiplier) || 3;
    const token = cfg.cron_token || '';
    document.getElementById('cfg-cron-url').value = token
      ? (location.origin + '/extensions/prmsecguard/cron?token=' + token)
      : '(token yok — üret)';

    const on = RULES.filter(r => cfg[r.key]?.enabled).length;
    document.getElementById('prmsec-rules-on').textContent = on + ' / ' + RULES.length;
    document.getElementById('prmsec-enabled').textContent = cfg.enabled ? 'Aktif' : 'Kapalı';
  }

  function readConfig() {
    const out = {
      enabled: document.getElementById('cfg-enabled').checked,
      retention_days: Number(document.getElementById('cfg-retention').value || 30),
      cron_interval_min: Number(document.getElementById('cfg-cron-int').value || 5),
      cron_token: cfgCache.cron_token || '',
      allowlist: {
        ips: document.getElementById('cfg-al-ips').value,
        actor_ids: document.getElementById('cfg-al-actors').value,
        server_ids: document.getElementById('cfg-al-servers').value,
      },
      mute_rules: document.getElementById('cfg-mute').value,
      notify: {
        enabled: document.getElementById('cfg-notify-en').checked,
        min_severity: document.getElementById('cfg-notify-min').value,
        webhook_url: document.getElementById('cfg-notify-hook').value.trim(),
        discord_webhook: document.getElementById('cfg-notify-discord').value.trim(),
        telegram_bot_token: document.getElementById('cfg-notify-tg-token').value.trim(),
        telegram_chat_id: document.getElementById('cfg-notify-tg-chat').value.trim(),
        auto_ban_auth_fail: document.getElementById('cfg-notify-autoban').checked,
      },
      baseline: {
        enabled: document.getElementById('cfg-baseline-en').checked,
        per_server: document.getElementById('cfg-baseline-server').checked,
        lookback_days: 7,
        multiplier: Number(document.getElementById('cfg-baseline-mult').value || 3),
      },
    };
    RULES.forEach(r => {
      const block = { enabled: !!document.querySelector(`[data-rule-en="${r.key}"]`)?.checked };
      r.fields.forEach(([k]) => {
        const input = document.querySelector(`[data-rule="${r.key}"][data-field="${k}"]`);
        const raw = input ? input.value : '';
        block[k] = (k === 'timezone') ? raw : Number(raw);
      });
      out[r.key] = block;
    });
    return out;
  }

  function renderAlerts(alerts) {
    tbody.innerHTML = '';
    if (!alerts.length) { empty.style.display = 'block'; return; }
    empty.style.display = 'none';
    alerts.forEach(a => {
      const tr = document.createElement('tr');
      const sev = a.severity || 'medium';
      const who = [a.actor_name || (a.actor_id ? ('#' + a.actor_id) : null), a.ip].filter(Boolean).join(' · ');
      const server = a.server_name ? `<div class="prmsec-muted">${esc(a.server_name)}</div>` : '';
      const banBtn = (banAvailable && a.ip && (a.rule === 'auth_fail_burst' || a.meta?.can_ban))
        ? `<button type="button" class="btn btn-xs btn-danger" data-ban="${esc(a.ip)}" data-alert="${esc(a.id)}">Ban</button>` : '';
      tr.innerHTML = `
        <td>${esc(fmtTs(a.ts))}</td>
        <td><span class="prmsec-sev ${esc(sev)}">${esc(sev)}</span></td>
        <td>${esc(ruleLabel[a.rule] || a.rule)}</td>
        <td><span class="prmsec-title">${esc(a.title || '')}</span><div class="prmsec-muted">${esc(a.detail || '')}</div>${server}</td>
        <td>${esc(who || '—')}</td>
        <td class="prmsec-row-actions">
          <button type="button" class="btn btn-xs btn-default" data-ctx="${esc(a.id)}">Detay</button>
          ${a.acked ? '<span class="prmsec-muted">OK</span>' : `<button type="button" class="btn btn-xs btn-default" data-ack="${esc(a.id)}">Onayla</button>`}
          ${banBtn}
        </td>`;
      tbody.appendChild(tr);
    });
  }

  async function loadContext(id) {
    const box = document.getElementById('prmsec-context-list');
    const hint = document.getElementById('prmsec-context-empty');
    hint.style.display = 'none';
    box.innerHTML = '<li class="prmsec-muted">Yükleniyor…</li>';
    try {
      const data = await api('/alerts/' + encodeURIComponent(id) + '/context');
      box.innerHTML = '';
      (data.activity || []).forEach(row => {
        const li = document.createElement('li');
        li.innerHTML = `<strong>${esc(row.event)}</strong> <span class="prmsec-muted">${esc(fmtTs(row.ts))} · ${esc(row.ip || '')}</span>`;
        box.appendChild(li);
      });
      if (!(data.activity || []).length) {
        hint.style.display = 'block';
        hint.textContent = 'Yakın aktivite bulunamadı.';
      }
    } catch (e) {
      hint.style.display = 'block';
      hint.textContent = e.message || String(e);
      box.innerHTML = '';
    }
  }

  function queryString() {
    const openOnly = document.getElementById('prmsec-open-only').checked;
    const sev = document.getElementById('prmsec-filter-sev').value;
    const rule = document.getElementById('prmsec-filter-rule').value;
    const q = document.getElementById('prmsec-filter-q').value.trim();
    const p = new URLSearchParams({ limit: '100', open: openOnly ? '1' : '0' });
    if (sev) p.set('severity', sev);
    if (rule) p.set('rule', rule);
    if (q) p.set('q', q);
    return p.toString();
  }

  async function refresh() {
    const [status, alerts] = await Promise.all([
      api('/status'),
      api('/alerts?' + queryString()),
    ]);
    status.config._ban = !!status.ban_available;
    fillConfig(status.config || {});
    banAvailable = !!status.ban_available;
    document.getElementById('prmsec-open').textContent = String(status.open_count || 0);
    renderAlerts(alerts.alerts || []);
    document.getElementById('prmsec-updated').textContent = 'Güncellendi ' + new Date().toLocaleTimeString();
    const csv = document.getElementById('prmsec-csv');
    csv.href = '/extensions/prmsecguard/alerts.csv?' + queryString();
  }

  buildRuleCards();

  document.getElementById('prmsec-refresh').onclick = () => refresh().catch(console.error);
  ['prmsec-open-only','prmsec-filter-sev','prmsec-filter-rule'].forEach(id => {
    document.getElementById(id).onchange = () => refresh().catch(console.error);
  });
  document.getElementById('prmsec-filter-q').onkeydown = (e) => {
    if (e.key === 'Enter') refresh().catch(console.error);
  };

  document.getElementById('prmsec-scan').onclick = async () => {
    const btn = document.getElementById('prmsec-scan');
    btn.disabled = true;
    try {
      const r = await api('/scan', { method: 'POST', body: JSON.stringify({ minutes: 60 }) });
      document.getElementById('prmsec-scan-meta').textContent = (r.scanned || 0) + ' / +' + (r.created || 0);
      await refresh();
    } catch (e) { alert(e.message || e); }
    finally { btn.disabled = false; }
  };

  document.getElementById('prmsec-ack-all').onclick = async () => {
    if (!confirm('Tüm açık uyarılar onaylansın mı?')) return;
    await api('/ack', { method: 'POST', body: JSON.stringify({ all: true }) });
    await refresh();
  };

  tbody.addEventListener('click', async (ev) => {
    const ack = ev.target.closest('[data-ack]');
    const ctx = ev.target.closest('[data-ctx]');
    const ban = ev.target.closest('[data-ban]');
    if (ack) {
      await api('/ack', { method: 'POST', body: JSON.stringify({ id: ack.getAttribute('data-ack') }) });
      await refresh();
    }
    if (ctx) loadContext(ctx.getAttribute('data-ctx'));
    if (ban) {
      if (!confirm('IP banlansın mı? ' + ban.getAttribute('data-ban'))) return;
      await api('/ban', { method: 'POST', body: JSON.stringify({
        ip: ban.getAttribute('data-ban'),
        alert_id: ban.getAttribute('data-alert'),
        note: 'SecGuard UI',
      })});
      await refresh();
    }
  });

  document.getElementById('cfg-cron-rotate').onclick = async () => {
    const body = readConfig();
    body.cron_token_rotate = true;
    const r = await api('/config', { method: 'POST', body: JSON.stringify(body) });
    fillConfig(r.config || {});
  };

  document.getElementById('prmsec-save').onclick = async () => {
    const msg = document.getElementById('prmsec-save-msg');
    msg.className = 'prmsec-msg';
    try {
      const r = await api('/config', { method: 'POST', body: JSON.stringify(readConfig()) });
      fillConfig(r.config || {});
      msg.textContent = 'Kaydedildi.';
      msg.className = 'prmsec-msg is-ok';
      await refresh();
    } catch (e) {
      msg.textContent = e.message || String(e);
      msg.className = 'prmsec-msg is-fail';
    }
  };

  refresh().catch(e => {
    empty.style.display = 'block';
    empty.textContent = 'Yüklenemedi: ' + (e.message || e);
  });
})();
</script>
