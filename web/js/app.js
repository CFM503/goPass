document.addEventListener('DOMContentLoaded', () => {
    connectWS();
    loadRules(); // Load rules initially for deduplication check
});

function connectWS() {
    const wsUrl = `ws://${window.location.host}/ws`;
    const socket = new WebSocket(wsUrl);

    socket.onopen = () => {
        document.getElementById('engine-status').classList.remove('red');
        document.getElementById('engine-status').classList.add('green');
    };

    socket.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            if (data.pid) {
                document.getElementById('sys-pid').innerText = data.pid;
            }
            document.getElementById('conn-count').innerText = data.connections || 0;
            document.getElementById('rx').innerText = data.rx || "0 B/s";
            document.getElementById('tx').innerText = data.tx || "0 B/s";

            if (data.active) {
                renderConnections(data.active);
            }
        } catch (e) {
            console.error(e);
        }
    };

    socket.onclose = () => {
        document.getElementById('engine-status').classList.remove('green');
        document.getElementById('engine-status').classList.add('red');
        setTimeout(connectWS, 3000);
    };
}

function renderConnections(conns) {
    const proxyBody = document.getElementById('conn-list-proxy');
    const directBody = document.getElementById('conn-list-direct');
    
    proxyBody.innerHTML = '';
    directBody.innerHTML = '';

    conns.forEach(c => {
        const tr = document.createElement('tr');
        if (c.policy === 'PROXY') {
            tr.innerHTML = `
                <td>${c.process}</td>
                <td>${c.target}</td>
                <td>${c.host}</td>
                <td><span style="color: var(--accent)">${c.policy}</span></td>
            `;
            proxyBody.appendChild(tr);
        } else {
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
        }
    });
}

window.quickAddRule = function(processName) {
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
    fetch('/api/settings')
        .then(res => res.json())
        .then(data => {
            if (data.mode === 'global') {
                document.getElementById('mode-global').checked = true;
            } else {
                document.getElementById('mode-whitelist').checked = true;
            }
        })
        .catch(console.error);
}

document.getElementById('save-settings-btn').addEventListener('click', () => {
    const isGlobal = document.getElementById('mode-global').checked;
    const mode = isGlobal ? 'global' : 'whitelist';

    fetch('/api/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode })
    })
        .then(res => res.json())
        .then(data => {
            if (data.status === 'ok') {
                alert('Settings saved successfully!');
            }
        })
        .catch(console.error);
});
