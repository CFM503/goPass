let uiConnLimit = 20;

document.addEventListener('DOMContentLoaded', () => {
    connectWS();
    loadRules(); // Load rules initially for deduplication check
});

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
            const pidEl = document.getElementById('sys-pid');
            if (pidEl && data.pid) pidEl.innerText = data.pid;

            const connEl = document.getElementById('conn-count');
            if (connEl) connEl.innerText = data.connections || 0;

            const rxEl = document.getElementById('rx-bytes');
            if (rxEl) rxEl.innerText = data.rx || "0 B/s";

            const txEl = document.getElementById('tx-bytes');
            if (txEl) txEl.innerText = data.tx || "0 B/s";

            if (data.active) {
                renderConnections(data.active);
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

function renderConnections(conns) {
    const proxyBody = document.getElementById('conn-list-proxy');
    const directBody = document.getElementById('conn-list-direct');

    proxyBody.innerHTML = '';
    directBody.innerHTML = '';

    const proxyConns = conns.filter(c => c.policy === 'PROXY').slice(0, uiConnLimit);
    const directConns = conns.filter(c => c.policy !== 'PROXY').slice(0, uiConnLimit);

    document.getElementById('proxy-title').innerText = `Proxied Connections (Top ${uiConnLimit})`;
    document.getElementById('direct-title').innerText = `Direct Connections (Top ${uiConnLimit})`;

    proxyConns.forEach(c => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${c.process}</td>
            <td>${c.target}</td>
            <td>${c.host}</td>
            <td><span style="color: var(--accent)">${c.policy}</span></td>
        `;
        proxyBody.appendChild(tr);
    });

    directConns.forEach(c => {
        const tr = document.createElement('tr');
        const isAlreadyWhitelisted = currentRules.some(r => r.payload === c.process);
        const buttonHtml = isAlreadyWhitelisted
            ? `<span style="color:var(--text-secondary); font-size:12px;">Already in Whitelist</span>`
            : `<button onclick="quickAddRule('${c.process}')" style="padding:4px 8px; background:var(--accent); border:none; color:white; border-radius:4px; cursor:pointer; font-size:12px;">Add to Rules</button>`;

        tr.innerHTML = `
            <td>${c.process}</td>
            <td>${c.target}</td>
            <td>${c.host}</td>
            <td>${buttonHtml}</td>
        `;
        directBody.appendChild(tr);
    });
}

window.quickAddRule = function (processName) {
    if (processName === 'unknown' || !processName) {
        alert("Cannot add unknown process.");
        return;
    }

    if (currentRules.some(r => r.payload === processName)) {
        alert("The program is already in the whitelist!");
        return;
    }

    currentRules.push({
        type: 'process',
        payload: processName,
        outbound: 'proxy'
    });

    saveRules();
    alert(`Successfully added ${processName} to whitelist!`);
};

// Navigation Logic
const navDashboard = document.getElementById('nav-dashboard');
const navRules = document.getElementById('nav-rules');
const navSettings = document.getElementById('nav-settings');

const viewDashboard = document.getElementById('view-dashboard');
const viewRules = document.getElementById('view-rules');
const viewSettings = document.getElementById('view-settings');

function switchView(viewId) {
    [navDashboard, navRules, navSettings].forEach(el => el.classList.remove('active'));
    [viewDashboard, viewRules, viewSettings].forEach(el => el.style.display = 'none');

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
    }
}

navDashboard.addEventListener('click', (e) => { e.preventDefault(); switchView('dashboard'); });
navRules.addEventListener('click', (e) => { e.preventDefault(); switchView('rules'); });
navSettings.addEventListener('click', (e) => { e.preventDefault(); switchView('settings'); });

// Rules API
let currentRules = [];

function loadRules() {
    fetch('/api/rules')
        .then(res => res.json())
        .then(data => {
            currentRules = data.rules || [];
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

    payloadInput.value = '';
    saveRules();
});

window.deleteRule = function (idx) {
    currentRules.splice(idx, 1);
    saveRules();
};

// Settings API
function loadSettings() {
    // Load Proxy Mode
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
        })
        .catch(console.error);

    // Load Upstream Proxy Settings
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
    if (isNaN(wsInterval) || wsInterval < 1) wsInterval = 3;

    let connLimit = parseInt(document.getElementById('ui-conn-limit').value, 10);
    if (isNaN(connLimit) || connLimit < 5) connLimit = 20;
    uiConnLimit = connLimit;

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
            body: JSON.stringify({ mode: mode, ws_refresh_interval: wsInterval, ui_conn_limit: connLimit })
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

