let uiConnLimit = 20;
let lastConnCount = -1;
let lastConnHash = 0;
let ruleSet = new Set();
let _domCache = null;

function getDOM() {
    if (_domCache) return _domCache;
    _domCache = {
        sysPid: document.getElementById('sys-pid'),
        connCount: document.getElementById('conn-count'),
        rxBytes: document.getElementById('rx-bytes'),
        txBytes: document.getElementById('tx-bytes'),
        proxyBody: document.getElementById('conn-list-proxy'),
        directBody: document.getElementById('conn-list-direct'),
        proxyTitle: document.getElementById('proxy-title'),
        directTitle: document.getElementById('direct-title'),
    };
    return _domCache;
}

document.addEventListener('DOMContentLoaded', () => {
    connectWS();
    loadRules();

    const proxyBody = document.getElementById('conn-list-proxy');
    const directBody = document.getElementById('conn-list-direct');

    if (proxyBody) {
        proxyBody.addEventListener('click', handleConnRowClick);
    }
    if (directBody) {
        directBody.addEventListener('click', handleConnRowClick);
    }
});

function handleConnRowClick(e) {
    const header = e.target.closest('.process-group-header');
    if (!header) return;
    header.classList.toggle('expanded');
    let next = header.nextElementSibling;
    while (next && next.classList.contains('process-group-child')) {
        next.classList.toggle('show');
        next = next.nextElementSibling;
    }
}

function connectWS() {
    const wsUrl = `ws://${window.location.host}/ws`;
    const socket = new WebSocket(wsUrl);

    socket.onopen = () => {
        const el = document.getElementById('engine-status');
        if (el) { el.classList.remove('red'); el.classList.add('green'); }
    };

    socket.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            const dom = getDOM();
            if (dom.sysPid && data.pid) dom.sysPid.innerText = data.pid;
            if (dom.connCount) dom.connCount.innerText = data.connections || 0;
            if (dom.rxBytes) dom.rxBytes.innerText = data.rx || "0 B/s";
            if (dom.txBytes) dom.txBytes.innerText = data.tx || "0 B/s";

            if (data.active) {
                const count = data.active.length;
                if (count !== lastConnCount) {
                    lastConnCount = count;
                    lastConnHash = 0;
                }
                if (count <= 50) {
                    let hash = 0;
                    for (let i = 0; i < count; i++) {
                        const c = data.active[i];
                        const s = c.process + c.target;
                        for (let j = 0; j < s.length; j++) {
                            hash = ((hash << 5) - hash + s.charCodeAt(j)) | 0;
                        }
                    }
                    if (hash !== lastConnHash) {
                        lastConnHash = hash;
                        renderConnections(data.active, dom);
                    }
                } else {
                    renderConnections(data.active, dom);
                }
            }
        } catch (e) {
            console.error(e);
        }
    };

    socket.onclose = () => {
        const el = document.getElementById('engine-status');
        if (el) { el.classList.remove('green'); el.classList.add('red'); }
        setTimeout(connectWS, 3000);
    };
}

function renderConnections(conns, dom) {
    if (!dom) dom = getDOM();

    const proxyConns = [];
    const directConns = [];
    for (let i = 0; i < conns.length && (proxyConns.length < uiConnLimit || directConns.length < uiConnLimit); i++) {
        if (conns[i].policy === 'PROXY' && proxyConns.length < uiConnLimit) {
            proxyConns.push(conns[i]);
        } else if (conns[i].policy !== 'PROXY' && directConns.length < uiConnLimit) {
            directConns.push(conns[i]);
        }
    }

    if (dom.proxyTitle) dom.proxyTitle.innerText = `Proxied Connections (Top ${uiConnLimit})`;
    if (dom.directTitle) dom.directTitle.innerText = `Direct Connections (Top ${uiConnLimit})`;

    renderGroupedConnections(dom.proxyBody, proxyConns, false);
    renderGroupedConnections(dom.directBody, directConns, true);
}

function renderGroupedConnections(tbody, conns, showAddButton) {
    const groups = {};
    for (let i = 0; i < conns.length; i++) {
        const name = conns[i].process || 'unknown';
        if (!groups[name]) groups[name] = [];
        groups[name].push(conns[i]);
    }

    const fragment = document.createDocumentFragment();
    const sortedKeys = Object.keys(groups).sort();

    for (let gi = 0; gi < sortedKeys.length; gi++) {
        const processName = sortedKeys[gi];
        const items = groups[processName];

        const headerTr = document.createElement('tr');
        headerTr.className = 'process-group-header';
        headerTr.dataset.process = processName;

        const isWhitelisted = ruleSet.has(processName);
        let actionHtml;
        if (showAddButton) {
            actionHtml = isWhitelisted
                ? '<span style="color:var(--text-secondary); font-size:12px;">Already in Whitelist</span>'
                : `<button onclick="event.stopPropagation(); quickAddRule('${processName}')" style="padding:4px 8px; background:var(--accent); border:none; color:white; border-radius:4px; cursor:pointer; font-size:12px;">Add to Rules</button>`;
        } else {
            actionHtml = isWhitelisted
                ? '<span style="color:var(--text-secondary); font-size:12px;">In Whitelist</span>'
                : `<button onclick="event.stopPropagation(); blockFromProxy('${processName}')" style="padding:4px 8px; background:#f85149; border:none; color:white; border-radius:4px; cursor:pointer; font-size:12px;">Block from Proxy</button>`;
        }

        const targetStr = items.length > 1 ? items.map(i => i.target).join(', ') : items[0].target;
        const hostStr = items.length > 1 ? items.map(i => i.host).join(', ') : items[0].host;

        headerTr.innerHTML = `<td>${processName}<span class="conn-count">${items.length}</span></td><td>${targetStr}</td><td>${hostStr}</td><td>${actionHtml}</td>`;
        fragment.appendChild(headerTr);

        items.sort((a, b) => a.target.localeCompare(b.target));
        const policyCell = showAddButton ? '<span style="color:var(--text-secondary); font-size:12px;">Direct</span>' : null;

        for (let ci = 0; ci < items.length; ci++) {
            const childTr = document.createElement('tr');
            childTr.className = 'process-group-child';
            childTr.innerHTML = `<td>${items[ci].target}</td><td>${items[ci].host}</td><td>${policyCell || `<span style="color: var(--accent)">${items[ci].policy}</span>`}</td>`;
            fragment.appendChild(childTr);
        }
    }

    tbody.innerHTML = '';
    tbody.appendChild(fragment);
}

window.quickAddRule = function (processName) {
    if (processName === 'unknown' || !processName) {
        alert("Cannot add unknown process.");
        return;
    }

    if (ruleSet.has(processName)) {
        alert("The program is already in the whitelist!");
        return;
    }

    currentRules.push({
        type: 'process',
        payload: processName,
        outbound: 'proxy'
    });
    ruleSet.add(processName);

    saveRules();
    alert(`Successfully added ${processName} to whitelist!`);
};

window.blockFromProxy = function (processName) {
    if (processName === 'unknown' || !processName) {
        alert("Cannot add unknown process.");
        return;
    }

    if (ruleSet.has(processName)) {
        alert("The program is already in the rules!");
        return;
    }

    currentRules.push({
        type: 'process',
        payload: processName,
        outbound: 'direct'
    });
    ruleSet.add(processName);

    saveRules();
    alert(`Successfully blocked ${processName} from using proxy!`);
};

const navDashboard = document.getElementById('nav-dashboard');
const navRules = document.getElementById('nav-rules');
const navSettings = document.getElementById('nav-settings');

const viewDashboard = document.getElementById('view-dashboard');
const viewRules = document.getElementById('view-rules');
const viewSettings = document.getElementById('view-settings');

function switchView(viewId) {
    navDashboard.classList.remove('active');
    navRules.classList.remove('active');
    navSettings.classList.remove('active');
    viewDashboard.style.display = 'none';
    viewRules.style.display = 'none';
    viewSettings.style.display = 'none';

    if (viewId === 'dashboard') {
        navDashboard.classList.add('active');
        viewDashboard.style.display = 'block';
    } else if (viewId === 'rules') {
        navRules.classList.add('active');
        viewRules.style.display = 'block';
        loadRules();
    } else if (viewId === 'settings') {
        navSettings.classList.add('active');
        viewSettings.style.display = 'block';
        loadSettings();
        loadSplitSettings();
    }
}

navDashboard.addEventListener('click', (e) => { e.preventDefault(); switchView('dashboard'); });
navRules.addEventListener('click', (e) => { e.preventDefault(); switchView('rules'); });
navSettings.addEventListener('click', (e) => { e.preventDefault(); switchView('settings'); });

let currentRules = [];

function loadRules() {
    fetch('/api/rules')
        .then(res => res.json())
        .then(data => {
            currentRules = data.rules || [];
            ruleSet = new Set(currentRules.map(r => r.payload));
            renderRules();
        })
        .catch(console.error);
}

function renderRules() {
    const list = document.getElementById('rules-list');
    if (currentRules.length > 0) {
        list.innerHTML = currentRules.map((r, idx) =>
            `<div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px; padding:10px; background:rgba(255,255,255,0.05); border-radius:4px;">
                <div><strong>${r.payload}</strong> (${r.type}) &rarr; ${r.outbound}</div>
                <button onclick="deleteRule(${idx})" style="padding:5px 10px; background:rgba(255,50,50,0.2); border:1px solid rgba(255,50,50,0.5); color:white; border-radius:4px; cursor:pointer;">Delete</button>
            </div>`
        ).join('');
    } else {
        list.innerHTML = "No rules configured.";
    }
}

function saveRules() {
    fetch('/api/rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rules: currentRules })
    })
        .then(res => res.json())
        .then(data => {
            if (data.status === 'ok') {
                renderRules();
            }
        })
        .catch(console.error);
}

document.getElementById('add-rule-btn').addEventListener('click', () => {
    const payloadInput = document.getElementById('new-rule-payload');
    const payload = payloadInput.value.trim();
    if (!payload) return;

    currentRules.push({
        type: 'process',
        payload: payload,
        outbound: 'proxy'
    });
    ruleSet.add(payload);

    payloadInput.value = '';
    saveRules();
});

window.deleteRule = function (idx) {
    ruleSet.delete(currentRules[idx].payload);
    currentRules.splice(idx, 1);
    saveRules();
};

function loadSettings() {
    fetch('/api/settings')
        .then(res => res.json())
        .then(data => {
            if (data.mode === 'global') {
                document.getElementById('mode-global').checked = true;
            } else {
                document.getElementById('mode-whitelist').checked = true;
            }
            if (data.ws_refresh_interval) {
                document.getElementById('ws-interval').value = data.ws_refresh_interval;
            }
            if (data.ui_conn_limit) {
                document.getElementById('ui-conn-limit').value = data.ui_conn_limit;
                uiConnLimit = data.ui_conn_limit;
            }
            if (data.show_direct_conns !== undefined) {
                document.getElementById('api-show-direct').checked = data.show_direct_conns;
            }
            if (data.direct_conns_limit) {
                document.getElementById('api-direct-limit').value = data.direct_conns_limit;
            }
        })
        .catch(console.error);

    fetch('/api/upstream')
        .then(res => res.json())
        .then(data => {
            if (data.type) document.getElementById('upstream-type').value = data.type;
            if (data.address) document.getElementById('upstream-addr').value = data.address;
            if (data.port) document.getElementById('upstream-port').value = data.port;
        })
        .catch(console.error);
}

document.getElementById('save-settings-btn').addEventListener('click', () => {
    const isGlobal = document.getElementById('mode-global').checked;
    const mode = isGlobal ? 'global' : 'whitelist';

    let wsInterval = parseInt(document.getElementById('ws-interval').value, 10);
    if (isNaN(wsInterval) || wsInterval < 1) wsInterval = 5;

    let connLimit = parseInt(document.getElementById('ui-conn-limit').value, 10);
    if (isNaN(connLimit) || connLimit < 5) connLimit = 20;
    uiConnLimit = connLimit;

    const showDirect = document.getElementById('api-show-direct').checked;
    let directLimit = parseInt(document.getElementById('api-direct-limit').value, 10);
    if (isNaN(directLimit) || directLimit < 1) directLimit = 20;

    const pType = document.getElementById('upstream-type').value;
    const pAddr = document.getElementById('upstream-addr').value.trim();
    const pPort = parseInt(document.getElementById('upstream-port').value, 10);

    if (!pAddr || isNaN(pPort)) {
        alert("Please enter a valid proxy address and port.");
        return;
    }

    const btn = document.getElementById('save-settings-btn');
    const msg = document.getElementById('settings-save-msg');
    btn.innerText = "Saving...";

    Promise.all([
        fetch('/api/settings', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                mode: mode,
                ws_refresh_interval: wsInterval,
                ui_conn_limit: connLimit,
                show_direct_conns: showDirect,
                direct_conns_limit: directLimit
            })
        }),
        fetch('/api/upstream', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ type: pType, address: pAddr, port: pPort })
        })
    ]).then(([resSettings, resUpstream]) => {
        return Promise.all([resSettings.json(), resUpstream.json()]);
    }).then(([dataSettings, dataUpstream]) => {
        btn.innerText = "Save Global Settings";
        if (dataSettings.status === 'ok' && dataUpstream.status === 'ok') {
            msg.style.display = 'inline-block';
            setTimeout(() => { msg.style.display = 'none'; }, 3000);
        } else {
            alert('Error saving some settings.');
        }
    }).catch(err => {
        console.error(err);
        btn.innerText = "Save Global Settings";
        alert("Network error while saving.");
    });
});

// ============================================================================
// Split Routing (绝对分流)
// ============================================================================

function splitStatusText(d) {
    const s = d.status || {};
    const lines = [];
    const modeNames = { geo: 'geo（纯地理）', process: 'process（纯进程白名单）', both: 'both（地理+进程）' };
    lines.push(`Mode: ${modeNames[d.mode] || d.mode} | Geo Priority: ${d.geo_priority ? 'ON' : 'OFF'} | CN Direct: ${d.cn_direct ? 'ON' : 'OFF'} | Foreign Proxy: ${d.foreign_proxy ? 'ON' : 'OFF'}`);
    lines.push(`IPv6: ${d.block_ipv6 ? 'BLOCKED' : 'allowed'} | Foreign UDP: ${d.block_foreign_udp ? 'BLOCKED' : 'allowed'} | DNS Relay: 127.0.0.1:${d.dns_relay_port}`);
    if (s.geosite_file || s.geoip_file) {
        lines.push(`Rules: geosite:cn ${s.geosite_cn_entries || 0} entries (${s.geosite_file || '-'}) | geoip:cn ${s.geoip_cn_cidrs || 0} CIDRs (${s.geoip_file || '-'})`);
    }
    lines.push(`Custom: direct ${s.custom_direct_domains || 0}D/${s.custom_direct_ips || 0}IP | proxy ${s.custom_proxy_domains || 0}D/${s.custom_proxy_ips || 0}IP | loaded: ${s.loaded_at || '-'}`);
    if (s.error) lines.push(`⚠️ ${s.error}`);
    return lines.join('\n');
}

function loadSplitSettings() {
    fetch('/api/split')
        .then(res => res.json())
        .then(d => {
            document.getElementById('split-status').innerText = splitStatusText(d);
            document.getElementById('split-enabled').checked = !!d.enabled;
            document.getElementById('split-mode').value = d.mode || 'both';
            document.getElementById('split-geo-priority').checked = d.geo_priority !== undefined ? d.geo_priority : true;
            document.getElementById('split-cn-direct').checked = d.cn_direct !== undefined ? d.cn_direct : true;
            document.getElementById('split-foreign-proxy').checked = d.foreign_proxy !== undefined ? d.foreign_proxy : true;
            document.getElementById('split-block-ipv6').checked = d.block_ipv6 !== undefined ? d.block_ipv6 : true;
            document.getElementById('split-block-foreign-udp').checked = d.block_foreign_udp !== undefined ? d.block_foreign_udp : true;
            document.getElementById('split-dns-relay-port').value = d.dns_relay_port || 5300;
            document.getElementById('split-system-dns').value = d.system_dns || '';
            document.getElementById('split-dot-server').value = d.dot_server || '1.1.1.1:853';
            document.getElementById('split-dot-sni').value = d.dot_sni || 'cloudflare-dns.com';
            document.getElementById('split-custom-direct').value = (d.custom_direct || []).join('\n');
            document.getElementById('split-custom-proxy').value = (d.custom_proxy || []).join('\n');
            document.getElementById('split-geosite-file').value = (d.rule_files && d.rule_files.geosite) || 'geosite.dat';
            document.getElementById('split-geoip-file').value = (d.rule_files && d.rule_files.geoip) || 'geoip.dat';
            document.getElementById('split-auto-update-hours').value = d.auto_update_hours || 0;
        })
        .catch(console.error);
}

document.getElementById('save-split-btn').addEventListener('click', () => {
    const split = {
        enabled: document.getElementById('split-enabled').checked,
        mode: document.getElementById('split-mode').value,
        geo_priority: document.getElementById('split-geo-priority').checked,
        cn_direct: document.getElementById('split-cn-direct').checked,
        foreign_proxy: document.getElementById('split-foreign-proxy').checked,
        block_ipv6: document.getElementById('split-block-ipv6').checked,
        block_foreign_udp: document.getElementById('split-block-foreign-udp').checked,
        dns_relay_port: parseInt(document.getElementById('split-dns-relay-port').value, 10) || 0,
        system_dns: document.getElementById('split-system-dns').value.trim(),
        dot_server: document.getElementById('split-dot-server').value.trim(),
        dot_sni: document.getElementById('split-dot-sni').value.trim(),
        custom_direct: document.getElementById('split-custom-direct').value.split('\n').map(s => s.trim()).filter(Boolean),
        custom_proxy: document.getElementById('split-custom-proxy').value.split('\n').map(s => s.trim()).filter(Boolean),
        auto_update_hours: parseInt(document.getElementById('split-auto-update-hours').value, 10) || 0,
        rule_files: {
            geosite: document.getElementById('split-geosite-file').value.trim(),
            geoip: document.getElementById('split-geoip-file').value.trim()
        }
    };

    fetch('/api/split', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(split)
    })
        .then(res => res.json())
        .then(data => {
            if (data.status === 'ok') {
                const msg = document.getElementById('split-save-msg');
                msg.style.display = 'inline-block';
                setTimeout(() => { msg.style.display = 'none'; }, 3000);
                loadSplitSettings();
            } else {
                alert('Error saving split settings.');
            }
        })
        .catch(err => {
            console.error(err);
            alert("Network error while saving split settings.");
        });
});

document.getElementById('update-rules-btn').addEventListener('click', () => {
    const btn = document.getElementById('update-rules-btn');
    const msg = document.getElementById('split-update-msg');
    btn.disabled = true;
    btn.innerText = "⏳ Updating...";
    msg.style.display = 'inline-block';
    msg.innerText = 'Downloading rule files...';

    fetch('/api/split/update-rules', { method: 'POST' })
        .then(res => res.json())
        .then(data => {
            btn.disabled = false;
            btn.innerText = "🔄 Update Rule Files";
            if (data.geosite_ok || data.geoip_ok) {
                msg.innerText = `✅ geosite ${data.geosite_ok ? 'OK' : 'SKIP'} | geoip ${data.geoip_ok ? 'OK' : 'SKIP'}`;
            } else {
                msg.innerText = `❌ ${data.error || 'Update failed'}`;
            }
            loadSplitSettings();
        })
        .catch(err => {
            btn.disabled = false;
            btn.innerText = "🔄 Update Rule Files";
            msg.innerText = `❌ ${err.message}`;
        });
});
