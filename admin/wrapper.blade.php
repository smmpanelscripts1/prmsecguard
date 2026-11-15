@php
  $isAdminIndex = request()->routeIs('admin.index');
@endphp

<style>
  .prmsec-banner {
    display: none; margin-bottom: 14px; padding: 10px 14px;
    background: #3b1d1d; border: 1px solid #7f1d1d; border-radius: 3px; color: #fecaca;
  }
  .prmsec-banner.is-show { display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; }
  .prmsec-nav-badge {
    display: inline-block; min-width: 18px; padding: 1px 6px; margin-left: 6px;
    border-radius: 9px; background: #dd4b39; color: #fff; font-size: 11px; font-weight: 700; line-height: 16px;
  }
</style>

@if($isAdminIndex)
  <div id="prmsec-banner" class="prmsec-banner">
    <div>
      <strong>SecGuard:</strong>
      <span id="prmsec-banner-text">Açık güvenlik uyarısı var.</span>
    </div>
    <a class="btn btn-sm btn-danger" href="/admin/extensions/prmsecguard">Uyarıları aç</a>
  </div>
@endif

<script>
(function () {
  function csrf() {
    var m = document.querySelector('meta[name="csrf-token"], meta[name="_token"]');
    if (m && m.content) return m.content;
    var input = document.querySelector('input[name="_token"]');
    return input ? input.value : '';
  }

  function showBanner(n) {
    var el = document.getElementById('prmsec-banner');
    var text = document.getElementById('prmsec-banner-text');
    if (!n) {
      if (el) el.classList.remove('is-show');
      return;
    }
    if (text) text.textContent = n + ' açık güvenlik uyarısı.';
    if (el) el.classList.add('is-show');
  }

  function badgeNav(n) {
    var links = document.querySelectorAll('a[href="/admin/extensions/prmsecguard"], a[href*="admin/extensions/prmsecguard"]');
    for (var i = 0; i < links.length; i++) {
      var link = links[i];
      var badge = link.querySelector('.prmsec-nav-badge');
      if (n <= 0) {
        if (badge) badge.remove();
        continue;
      }
      if (!badge) {
        badge = document.createElement('span');
        badge.className = 'prmsec-nav-badge';
        link.appendChild(badge);
      }
      badge.textContent = String(n);
    }
  }

  fetch('/extensions/prmsecguard/status', {
    headers: { 'Accept': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
    credentials: 'same-origin',
  }).then(function (r) { return r.json(); }).then(function (data) {
    var n = Number(data.open_count || 0);
    showBanner(n);
    badgeNav(n);
  }).catch(function () {});

  @if($isAdminIndex)
  fetch('/extensions/prmsecguard/scan', {
    method: 'POST',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
      'X-Requested-With': 'XMLHttpRequest',
      'X-CSRF-TOKEN': csrf(),
      'X-XSRF-TOKEN': csrf(),
    },
    credentials: 'same-origin',
    body: JSON.stringify({ minutes: 30, _token: csrf() }),
  }).then(function (r) { return r.json(); }).then(function (data) {
    var n = Number(data.open || 0);
    showBanner(n);
    badgeNav(n);
  }).catch(function () {});
  @endif
})();
</script>
