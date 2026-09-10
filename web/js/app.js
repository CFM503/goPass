let uiConnLimit = 20;
let lastConnHash = 0;
let _domCache = null;

function getDOM() {
    if (_domCache) return _domCache;
    _domCache = {
        sysPid: document.getElementById('sys-pid'),
        connCount: document.getElementById('conn-count'),
        rxBytes: document.getElementById('rx-bytes'),
        txBytes: document.getElementById('tx-bytes'),
        proxyBody: document.getElementById('conn-list-proxy'),
        proxyTitle: document.getElementById('proxy-title'),
        directTitle: document.getElementById('direct-title'),
        directBody: document.getElementById('conn-list-direct')
    };
    return _domCache;
}

document.addEventListener('DOMContentLoaded', () => {
    connectWS();
    loadSettings();
    loadUpstream();
    loadPerformance();
    const dashboard = document.getElementById('nav-dashboard');
    const settings = document.getElementById('nav-settings');
    const dashboardView = document.getElementById('view-dashboard');
    const settingsView = document.getElementById('view-settings');
    if (dashboard && settings && dashboardView && settingsView) {
        dashboard.addEventListener('click', e => { e.preventDefault(); dashboard.classList.add('active'); settings.classList.remove('active'); dashboardView.style.display='block'; settingsView.style.display='none'; });
        settings.addEventListener('click', e => { e.preventDefault(); settings.classList.add('active'); dashboard.classList.remove('active'); dashboardView.style.display='none'; settingsView.style.display='block'; });
    }
    const saveButton = document.getElementById('save-settings-btn');
    if (saveButton) saveButton.addEventListener('click', saveSettings);
});

function connectWS() {
    const socket = new WebSocket(`ws://${window.location.host}/ws`);
    socket.onopen = () => setEngineStatus(true);
    socket.onmessage = event => {
        try {
            const data = JSON.parse(event.data);
            const dom = getDOM();
            if (dom.sysPid) dom.sysPid.innerText = data.pid ?? 0;
            if (dom.connCount) dom.connCount.innerText = data.connections ?? 0;
            if (dom.rxBytes) dom.rxBytes.innerText = data.rx || '0 B/s';
            if (dom.txBytes) dom.txBytes.innerText = data.tx || '0 B/s';
            renderConnections(Array.isArray(data.active) ? data.active : [], dom);
        } catch (err) { console.error('invalid websocket message', err); }
    };
    socket.onclose = () => { setEngineStatus(false); setTimeout(connectWS, 3000); };
    socket.onerror = () => socket.close();
}

function setEngineStatus(ready) {
    const el = document.getElementById('engine-status');
    if (!el) return;
    el.classList.toggle('green', ready);
    el.classList.toggle('red', !ready);
}

function renderConnections(conns, dom = getDOM()) {
    const visible = conns.slice(0, Math.max(1, uiConnLimit));
    const hashInput = visible.map(c => `${c.id || ''}|${c.target || ''}`).join('\n');
    let hash = 0;
    for (let i = 0; i < hashInput.length; i++) hash = ((hash << 5) - hash + hashInput.charCodeAt(i)) | 0;
    if (hash === lastConnHash && visible.length === conns.length) return;
    lastConnHash = hash;
    if (dom.proxyTitle) dom.proxyTitle.innerText = `Proxied Connections (Top ${uiConnLimit})`;
    if (dom.proxyBody) {
        dom.proxyBody.innerHTML = visible.length
            ? visible.map(c => `<tr><td>${escapeHtml(c.target || 'unknown')}</td><td>${escapeHtml(c.host || '')}</td><td><span style="color:var(--accent)">PROXY</span></td></tr>`).join('')
            : '<tr><td colspan="3">No active proxied connections.</td></tr>';
    }
    if (dom.directTitle) dom.directTitle.innerText = 'Direct Connections (disabled)';
    if (dom.directBody) dom.directBody.innerHTML = '<tr><td colspan="3">Direct/split routing is disabled in GoPass v1.6.7.</td></tr>';
}

function escapeHtml(value) { return String(value).replace(/[&<>'"]/g, ch => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', "'":'&#39;', '"':'&quot;' }[ch])); }

function loadSettings() {
    fetch('/api/settings').then(checkResponse).then(data => {
        const ws = document.getElementById('ws-interval');
        const limit = document.getElementById('ui-conn-limit');
        if (ws && Number.isFinite(data.ws_refresh_interval)) ws.value = data.ws_refresh_interval;
        if (limit && Number.isFinite(data.ui_conn_limit)) { limit.value = data.ui_conn_limit; uiConnLimit = Math.max(1, Number(data.ui_conn_limit)); }
    }).catch(console.error);
}

function loadUpstream() {
    fetch('/api/upstream').then(checkResponse).then(data => {
        const type = document.getElementById('upstream-type');
        const addr = document.getElementById('upstream-addr');
        const port = document.getElementById('upstream-port');
        if (type && data.type) type.value = data.type;
        if (addr && data.address) addr.value = data.address;
        if (port && data.port) port.value = data.port;
    }).catch(console.error);
}

function loadPerformance() {
    fetch('/api/performance').then(checkResponse).then(data => {
        const select = document.getElementById('relay-buffer-size');
        if (select && Number.isFinite(data.buffer_size)) {
            const value = Math.min(1048576, Math.max(32768, Number(data.buffer_size)));
            select.value = String(value);
        }
    }).catch(console.error);
}

async function saveSettings() {
    const btn = document.getElementById('save-settings-btn');
    const msg = document.getElementById('settings-save-msg');
    const wsInput = document.getElementById('ws-interval');
    const limitInput = document.getElementById('ui-conn-limit');
    const typeInput = document.getElementById('upstream-type');
    const addrInput = document.getElementById('upstream-addr');
    const portInput = document.getElementById('upstream-port');
    const bufferInput = document.getElementById('relay-buffer-size');

    let wsInterval = Number.parseInt(wsInput?.value || '5', 10);
    let connLimit = Number.parseInt(limitInput?.value || '20', 10);
    const type = typeInput?.value || 'socks5';
    const address = (addrInput?.value || '').trim();
    const port = Number.parseInt(portInput?.value || '0', 10);
    const bufferSize = Number.parseInt(bufferInput?.value || '262144', 10);
    if (!Number.isFinite(wsInterval) || wsInterval < 1) wsInterval = 5;
    if (!Number.isFinite(connLimit) || connLimit < 1) connLimit = 20;
    if (!Number.isFinite(bufferSize) || bufferSize < 32768 || bufferSize > 1048576) { alert('Relay buffer must be between 32 KB and 1 MB.'); return; }
    if (!address || !Number.isInteger(port) || port < 1 || port > 65535) { alert('Please enter a valid upstream address and port.'); return; }

    if (btn) btn.innerText = 'Saving...';
    try {
        const [settingsRes, upstreamRes, perfRes] = await Promise.all([
            fetch('/api/settings', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ ws_refresh_interval:wsInterval, ui_conn_limit:connLimit }) }),
            fetch('/api/upstream', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ type, address, port }) }),
            fetch('/api/performance', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ buffer_size:bufferSize, tcp_nodelay:true, tcp_keep_alive:true, keep_alive_period:15, tcp_linger:-1 }) })
        ]);
        const settings = await settingsRes.json();
        const upstream = await upstreamRes.json();
        const perf = await perfRes.json();
        if (settings.status !== 'ok' || upstream.status !== 'ok' || perf.status !== 'ok') throw new Error('save failed');
        uiConnLimit = connLimit;
        if (msg) { msg.style.display='inline-block'; setTimeout(() => { msg.style.display='none'; }, 3000); }
    } catch (err) { console.error(err); alert('Failed to save settings.'); }
    finally { if (btn) btn.innerText = 'Save Settings'; }
}

function checkResponse(res) { if (!res.ok) throw new Error(`HTTP ${res.status}`); return res.json(); }
