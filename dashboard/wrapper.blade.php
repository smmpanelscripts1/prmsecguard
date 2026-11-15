{{-- PRM SecGuard: sample websocket console commands (client-side hook). --}}
<script>
(function () {
  if (window.__prmSecGuardWsHook) return;
  window.__prmSecGuardWsHook = true;

  function csrf() {
    var m = document.querySelector('meta[name="csrf-token"], meta[name="_token"]');
    if (m && m.content) return m.content;
    var input = document.querySelector('input[name="_token"]');
    return input ? input.value : '';
  }

  function serverUuid() {
    var m = location.pathname.match(/\/server\/([0-9a-fA-F-]{8,})/);
    return m ? m[1] : '';
  }

  function report(command) {
    var uuid = serverUuid();
    if (!uuid || !command) return;
    try {
      fetch('/extensions/prmsecguard/console-sample', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
          'X-CSRF-TOKEN': csrf(),
          'X-XSRF-TOKEN': csrf(),
          'X-Requested-With': 'XMLHttpRequest',
        },
        body: JSON.stringify({
          _token: csrf(),
          server_uuid: uuid,
          command: String(command).slice(0, 500),
          source: 'websocket',
        }),
      }).catch(function () {});
    } catch (e) {}
  }

  function inspectPayload(data) {
    try {
      var msg = typeof data === 'string' ? JSON.parse(data) : data;
      if (!msg || typeof msg !== 'object') return;
      var ev = msg.event || msg[0];
      if (ev !== 'send command') return;
      var args = msg.args || msg[1] || [];
      var cmd = Array.isArray(args) ? args[0] : args;
      if (cmd) report(cmd);
    } catch (e) {}
  }

  var proto = WebSocket.prototype;
  var origSend = proto.send;
  proto.send = function (data) {
    try { inspectPayload(data); } catch (e) {}
    return origSend.apply(this, arguments);
  };
})();
</script>
