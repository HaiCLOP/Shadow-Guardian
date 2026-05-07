/**
 * Shadow Guardian — Dashboard Application
 * 
 * Handles auth flow, data polling, and UI rendering.
 * Polls API every 3 seconds for live updates.
 */

(function() {
    'use strict';

    // ─── State ──────────────────────────────────────────────────
    const API_BASE = window.location.origin;
    let authToken = sessionStorage.getItem('sg_auth_token') || '';
    let pollInterval = null;
    let isConnected = false;

    // ─── DOM Refs ───────────────────────────────────────────────
    const $ = (sel) => document.querySelector(sel);
    const $$ = (sel) => document.querySelectorAll(sel);

    const dom = {
        setupOverlay: $('#setup-overlay'),
        loginOverlay: $('#login-overlay'),
        dashboard: $('#dashboard'),
        setupForm: $('#setup-form'),
        loginForm: $('#login-form'),
        setupError: $('#setup-error'),
        loginError: $('#login-error'),
        cloudSyncCheck: $('#setup-cloud-sync'),
        cloudFields: $('#cloud-fields'),
        connectionStatus: $('#connection-status'),
        statCpu: $('#stat-cpu'),
        statMem: $('#stat-mem'),
        statUptime: $('#stat-uptime'),
        appsTree: $('#apps-tree'),
        appsCount: $('#apps-count'),
        sessionTimeline: $('#session-timeline'),
        sessionsCount: $('#sessions-count'),
        alertsList: $('#alerts-list'),
        alertsCount: $('#alerts-count'),
        webjailToggle: $('#webjail-toggle'),
        webjailDomains: $('#webjail-domains'),
        webjailApply: $('#webjail-apply'),
        webjailStatus: $('#webjail-status'),
        browserTbody: $('#browser-tbody'),
        browserCount: $('#browser-count'),
        windowsTbody: $('#windows-tbody'),
        windowsCount: $('#windows-count'),
        usbTbody: $('#usb-tbody'),
        usbCount: $('#usb-count'),
        clipboardTbody: $('#clipboard-tbody'),
        clipboardCount: $('#clipboard-count'),
        filesTbody: $('#files-tbody'),
        filesCount: $('#files-count'),
    };

    // ─── API Helper ─────────────────────────────────────────────

    async function api(path, options = {}) {
        const headers = { 'Content-Type': 'application/json' };
        if (authToken) {
            headers['Authorization'] = `Bearer ${authToken}`;
        }
        
        try {
            const resp = await fetch(`${API_BASE}${path}`, {
                ...options,
                headers: { ...headers, ...options.headers },
                credentials: 'same-origin',
            });
            
            const data = await resp.json();
            
            if (resp.status === 401) {
                authToken = '';
                sessionStorage.removeItem('sg_auth_token');
                showLogin();
                throw new Error('Auth required');
            }
            if (resp.status === 403 && data.setup_required) {
                showSetup();
                throw new Error('Setup required');
            }
            
            return { ok: resp.ok, status: resp.status, data };
        } catch (err) {
            if (err.message !== 'Auth required' && err.message !== 'Setup required') {
                setConnectionStatus('offline');
            }
            throw err;
        }
    }

    // ─── Auth Flow ──────────────────────────────────────────────

    async function checkAuthState() {
        try {
            const { data } = await api('/api/setup/status');
            
            if (!data.setup_complete) {
                showSetup();
                return;
            }
            
            // Try fetching data with stored token
            try {
                await api('/api/status');
                showDashboard();
            } catch {
                showLogin();
            }
        } catch {
            showLogin();
        }
    }

    function showSetup() {
        dom.setupOverlay.classList.remove('hidden');
        dom.loginOverlay.classList.add('hidden');
        dom.dashboard.classList.add('hidden');
        stopPolling();
    }

    function showLogin() {
        dom.setupOverlay.classList.add('hidden');
        dom.loginOverlay.classList.remove('hidden');
        dom.dashboard.classList.add('hidden');
        stopPolling();
    }

    function showDashboard() {
        dom.setupOverlay.classList.add('hidden');
        dom.loginOverlay.classList.add('hidden');
        dom.dashboard.classList.remove('hidden');
        startPolling();
    }

    // ─── Setup Form ─────────────────────────────────────────────

    dom.setupForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        dom.setupError.classList.add('hidden');

        const password = $('#setup-password').value;
        const confirm = $('#setup-password-confirm').value;

        if (password !== confirm) {
            dom.setupError.textContent = 'Passwords do not match';
            dom.setupError.classList.remove('hidden');
            return;
        }

        const body = { password };
        
        if (dom.cloudSyncCheck.checked) {
            body.cloud_sync_enabled = true;
            body.supabase_url = $('#setup-supabase-url').value;
            body.supabase_key = $('#setup-supabase-key').value;
        }

        try {
            const { ok, data } = await api('/api/setup', {
                method: 'POST',
                body: JSON.stringify(body),
            });

            if (ok) {
                authToken = data.auth_token;
                sessionStorage.setItem('sg_auth_token', authToken);
                showDashboard();
            } else {
                dom.setupError.textContent = data.error || 'Setup failed';
                dom.setupError.classList.remove('hidden');
            }
        } catch (err) {
            dom.setupError.textContent = 'Connection failed';
            dom.setupError.classList.remove('hidden');
        }
    });

    dom.cloudSyncCheck.addEventListener('change', () => {
        dom.cloudFields.classList.toggle('hidden', !dom.cloudSyncCheck.checked);
    });

    // ─── Login Form ─────────────────────────────────────────────

    dom.loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        dom.loginError.classList.add('hidden');

        const password = $('#login-password').value;

        try {
            const { ok, data } = await api('/api/auth', {
                method: 'POST',
                body: JSON.stringify({ password }),
            });

            if (ok) {
                authToken = data.auth_token;
                sessionStorage.setItem('sg_auth_token', authToken);
                showDashboard();
            } else {
                dom.loginError.textContent = data.error || 'Authentication failed';
                dom.loginError.classList.remove('hidden');
            }
        } catch (err) {
            dom.loginError.textContent = 'Connection failed';
            dom.loginError.classList.remove('hidden');
        }
    });

    // ─── Data Polling ───────────────────────────────────────────

    function startPolling() {
        if (pollInterval) return;
        fetchAllData();
        pollInterval = setInterval(fetchAllData, 3000);
    }

    function stopPolling() {
        if (pollInterval) {
            clearInterval(pollInterval);
            pollInterval = null;
        }
    }

    async function fetchAllData() {
        try {
            const [appsResp, sessionsResp, alertsResp, statusResp,
                   browserResp, windowsResp, usbResp, clipboardResp, filesResp] = await Promise.allSettled([
                api('/api/apps?limit=25'),
                api('/api/sessions?limit=20'),
                api('/api/alerts?limit=20'),
                api('/api/status'),
                api('/api/browser-history?limit=30'),
                api('/api/all-windows'),
                api('/api/usb-events?limit=20'),
                api('/api/clipboard-log?limit=20'),
                api('/api/file-events?limit=30'),
            ]);

            setConnectionStatus('online');

            if (appsResp.status === 'fulfilled' && appsResp.value.ok) {
                renderApps(appsResp.value.data.data || []);
            }
            if (sessionsResp.status === 'fulfilled' && sessionsResp.value.ok) {
                renderSessions(sessionsResp.value.data.data || []);
            }
            if (alertsResp.status === 'fulfilled' && alertsResp.value.ok) {
                renderAlerts(alertsResp.value.data.data || []);
            }
            if (statusResp.status === 'fulfilled' && statusResp.value.ok) {
                renderStatus(statusResp.value.data);
            }
            if (browserResp.status === 'fulfilled' && browserResp.value.ok) {
                renderBrowserHistory(browserResp.value.data.data || []);
            }
            if (windowsResp.status === 'fulfilled' && windowsResp.value.ok) {
                renderAllWindows(windowsResp.value.data.data || []);
            }
            if (usbResp.status === 'fulfilled' && usbResp.value.ok) {
                renderUSBEvents(usbResp.value.data.data || []);
            }
            if (clipboardResp.status === 'fulfilled' && clipboardResp.value.ok) {
                renderClipboardLog(clipboardResp.value.data.data || []);
            }
            if (filesResp.status === 'fulfilled' && filesResp.value.ok) {
                renderFileEvents(filesResp.value.data.data || []);
            }
        } catch (err) {
            setConnectionStatus('offline');
        }
    }

    // ─── Renderers ──────────────────────────────────────────────

    function setConnectionStatus(status) {
        isConnected = status === 'online';
        dom.connectionStatus.textContent = status === 'online' ? 'Connected' : 
                                            status === 'offline' ? 'Disconnected' : 'Connecting';
        dom.connectionStatus.className = `status-badge status-${status}`;
    }

    // ─── App Icon Config ────────────────────────────────────────
    const APP_ICONS = {
        'brave.exe':     { color: '#FB542B', label: 'B', name: 'Brave' },
        'chrome.exe':    { color: '#4285F4', label: 'C', name: 'Google Chrome' },
        'msedge.exe':    { color: '#0078D4', label: 'E', name: 'Microsoft Edge' },
        'firefox.exe':   { color: '#FF7139', label: 'F', name: 'Firefox' },
        'spotify.exe':   { color: '#1DB954', label: 'S', name: 'Spotify' },
        'discord.exe':   { color: '#5865F2', label: 'D', name: 'Discord' },
        'code.exe':      { color: '#007ACC', label: 'VS', name: 'VS Code' },
        'explorer.exe':  { color: '#FFB900', label: 'E', name: 'File Explorer' },
        'notepad.exe':   { color: '#6B7280', label: 'N', name: 'Notepad' },
        'cmd.exe':       { color: '#1E1E1E', label: '>', name: 'Command Prompt' },
        'powershell.exe':{ color: '#012456', label: 'PS', name: 'PowerShell' },
        'windowsterminal.exe': { color: '#4D4D4D', label: 'WT', name: 'Windows Terminal' },
        'teams.exe':     { color: '#6264A7', label: 'T', name: 'Microsoft Teams' },
        'slack.exe':     { color: '#4A154B', label: 'S', name: 'Slack' },
        'outlook.exe':   { color: '#0078D4', label: 'O', name: 'Outlook' },
        'winword.exe':   { color: '#2B579A', label: 'W', name: 'Microsoft Word' },
        'excel.exe':     { color: '#217346', label: 'X', name: 'Microsoft Excel' },
        'vlc.exe':       { color: '#FF8800', label: 'V', name: 'VLC' },
        'antigravity.exe': { color: '#00D4FF', label: 'AG', name: 'Antigravity' },
        'taskmgr.exe':   { color: '#0078D4', label: 'TM', name: 'Task Manager' },
        'devenv.exe':    { color: '#68217A', label: 'VS', name: 'Visual Studio' },
        'python.exe':    { color: '#3776AB', label: 'Py', name: 'Python' },
        'pythonw.exe':   { color: '#3776AB', label: 'Py', name: 'Python' },
        'python3.11.exe':{ color: '#3776AB', label: 'Py', name: 'Python' },
        'node.exe':      { color: '#339933', label: 'N', name: 'Node.js' },
    };

    function getAppIcon(processName) {
        const key = (processName || '').toLowerCase();
        if (APP_ICONS[key]) return APP_ICONS[key];
        // Generate a stable color from process name hash
        let hash = 0;
        for (let i = 0; i < key.length; i++) hash = key.charCodeAt(i) + ((hash << 5) - hash);
        const hue = Math.abs(hash) % 360;
        return {
            color: `hsl(${hue}, 55%, 45%)`,
            label: (processName || '?')[0].toUpperCase(),
            name: processName ? processName.replace(/\.exe$/i, '') : 'Unknown',
        };
    }

    // Track expanded state across renders
    const expandedApps = new Set();

    function renderApps(apps) {
        dom.appsCount.textContent = apps.length;

        if (apps.length === 0) {
            dom.appsTree.innerHTML = '<div class="empty-state">No app activity recorded</div>';
            return;
        }

        // Group by process_name
        const groups = new Map();
        for (const app of apps) {
            const key = app.process_name || 'unknown';
            if (!groups.has(key)) {
                groups.set(key, {
                    process_name: key,
                    exe_path: app.exe_path || '',
                    windows: [],
                    hasForeground: false,
                    totalDuration: 0,
                });
            }
            const g = groups.get(key);
            g.windows.push(app);
            g.totalDuration += (app.duration || 0);
            if (app.is_foreground) g.hasForeground = true;
        }

        // Sort: foreground first, then by window count
        const sorted = [...groups.values()].sort((a, b) => {
            if (a.hasForeground !== b.hasForeground) return a.hasForeground ? -1 : 1;
            return b.windows.length - a.windows.length;
        });

        dom.appsTree.innerHTML = sorted.map(group => {
            const icon = getAppIcon(group.process_name);
            const isExpanded = expandedApps.has(group.process_name);
            const fgClass = group.hasForeground ? ' is-foreground' : '';
            const expandClass = isExpanded ? ' expanded' : '';
            const uniquePids = [...new Set(group.windows.map(w => w.pid))];

            const childRows = group.windows.map(w => `
                <div class="app-child-row" title="${escHtml(w.exe_path || '')}">
                    <svg class="app-child-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 9h18"/></svg>
                    <span class="app-child-title">${escHtml(w.window_title || 'Untitled')}</span>
                    <span class="app-child-pid">PID ${w.pid || '?'}</span>
                    ${w.is_foreground ? '<span class="app-child-fg" title="Foreground"></span>' : ''}
                </div>
            `).join('');

            return `
            <div class="app-group${expandClass}" data-process="${escHtml(group.process_name)}">
                <div class="app-group-header${fgClass}">
                    <div class="app-icon" style="background:${icon.color}">${icon.label}</div>
                    <div class="app-group-info">
                        <div class="app-group-name">${escHtml(icon.name)}</div>
                        <div class="app-group-meta">${escHtml(group.process_name)} · ${formatDuration(group.totalDuration)} · PID ${uniquePids.join(', ')}</div>
                    </div>
                    <div class="app-group-right">
                        <span class="app-window-count">${group.windows.length} window${group.windows.length !== 1 ? 's' : ''}</span>
                        <svg class="app-expand-arrow" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"/></svg>
                    </div>
                </div>
                <div class="app-children">
                    ${childRows}
                </div>
            </div>
            `;
        }).join('');
    }

    // Event delegation for expand/collapse (avoids inline onclick / CSP issues)
    dom.appsTree.addEventListener('click', function(e) {
        const header = e.target.closest('.app-group-header');
        if (!header) return;
        const group = header.closest('.app-group');
        if (!group) return;
        const processName = group.dataset.process;
        group.classList.toggle('expanded');
        if (group.classList.contains('expanded')) {
            expandedApps.add(processName);
        } else {
            expandedApps.delete(processName);
        }
    });

    function renderSessions(sessions) {
        dom.sessionsCount.textContent = sessions.length;

        if (sessions.length === 0) {
            dom.sessionTimeline.innerHTML = '<div class="empty-state">No session events recorded</div>';
            return;
        }

        dom.sessionTimeline.innerHTML = sessions.map(s => `
            <div class="timeline-item event-${s.event_type || 'unknown'}">
                <div class="timeline-event">${escHtml(s.event_type || 'Unknown')}</div>
                <div class="timeline-meta">
                    ${formatTimestamp(s.timestamp)} · Session ${s.session_id || '?'} · ${escHtml(s.username || 'Unknown')}
                </div>
            </div>
        `).join('');
    }

    function renderAlerts(alerts) {
        const unacked = alerts.filter(a => !a.acknowledged);
        dom.alertsCount.textContent = unacked.length;

        if (alerts.length === 0) {
            dom.alertsList.innerHTML = '<div class="empty-state">No security alerts — system clean</div>';
            return;
        }

        dom.alertsList.innerHTML = alerts.map(a => `
            <div class="alert-item severity-${a.severity || 'info'}" data-id="${a.id}">
                <span class="alert-severity">${a.severity || 'info'}</span>
                <div class="alert-content">
                    <div class="alert-message">${escHtml(a.message || 'Alert')}</div>
                    <div class="alert-time">${formatTimestamp(a.timestamp)} · ${escHtml(a.alert_type || '')}</div>
                </div>
                ${!a.acknowledged ? `<button class="alert-ack" onclick="ackAlert(${a.id})">ACK</button>` : ''}
            </div>
        `).join('');
    }

    function renderStatus(status) {
        if (status.cpu_percent !== undefined) {
            dom.statCpu.textContent = `${status.cpu_percent.toFixed(1)}%`;
        }
        if (status.memory_mb !== undefined) {
            dom.statMem.textContent = `${status.memory_mb.toFixed(0)}MB`;
        }
        if (status.uptime !== undefined) {
            dom.statUptime.textContent = formatUptime(status.uptime);
        }

        // Update WebJail status
        if (status.webjail) {
            const wjEnabled = status.webjail.enabled;
            dom.webjailToggle.checked = wjEnabled;
            dom.webjailStatus.textContent = wjEnabled ? 'Active' : 'Disabled';
            dom.webjailStatus.className = `status-badge ${wjEnabled ? 'status-on' : 'status-off'}`;

            // Pre-populate domains textarea if it's empty (first load)
            if (status.webjail.blocked_domains && status.webjail.blocked_domains.length > 0) {
                if (!dom.webjailDomains.value.trim()) {
                    dom.webjailDomains.value = status.webjail.blocked_domains.join('\n');
                }
            }
        }
    }

    // ─── New Section Renderers ──────────────────────────────────

    function renderBrowserHistory(entries) {
        dom.browserCount.textContent = entries.length;
        if (entries.length === 0) {
            dom.browserTbody.innerHTML = '<tr class="empty-row"><td colspan="4">No browser history captured</td></tr>';
            return;
        }
        dom.browserTbody.innerHTML = entries.map(e => `
            <tr>
                <td><span style="color:var(--violet)">${escHtml(e.browser || '—')}</span></td>
                <td title="${escHtml(e.title || '')}">${truncate(e.title || '—', 35)}</td>
                <td title="${escHtml(e.url || '')}"><a href="${escHtml(e.url || '#')}" target="_blank" style="color:var(--text-secondary);text-decoration:none;">${truncate(e.url || '—', 40)}</a></td>
                <td>${formatTimestamp(e.visit_time || e.timestamp)}</td>
            </tr>
        `).join('');
    }

    function renderAllWindows(windows) {
        dom.windowsCount.textContent = windows.length;
        if (windows.length === 0) {
            dom.windowsTbody.innerHTML = '<tr class="empty-row"><td colspan="5">No windows detected</td></tr>';
            return;
        }
        dom.windowsTbody.innerHTML = windows.map(w => `
            <tr${w.is_foreground ? ' style="background:var(--cyan-muted)"' : ''}>
                <td>${escHtml(w.process_name || '—')}</td>
                <td title="${escHtml(w.window_title || '')}">${truncate(w.window_title || '—', 35)}</td>
                <td style="color:var(--teal)">${escHtml(w.tab_title || '—')}</td>
                <td>${w.pid || '—'}</td>
                <td>${w.is_foreground ? '<span style="color:var(--green)">●</span>' : ''}</td>
            </tr>
        `).join('');
    }

    function renderUSBEvents(events) {
        dom.usbCount.textContent = events.length;
        if (events.length === 0) {
            dom.usbTbody.innerHTML = '<tr class="empty-row"><td colspan="4">No USB events</td></tr>';
            return;
        }
        dom.usbTbody.innerHTML = events.map(e => {
            const actionColor = e.action === 'connected' ? 'var(--green)' : 'var(--red)';
            return `
            <tr>
                <td>${escHtml(e.device_name || '—')}</td>
                <td><span style="color:${actionColor};font-weight:600">${escHtml(e.action || '—')}</span></td>
                <td title="${escHtml(e.device_id || '')}">${truncate(e.device_id || '—', 30)}</td>
                <td>${formatTimestamp(e.timestamp)}</td>
            </tr>
            `;
        }).join('');
    }

    function renderClipboardLog(entries) {
        dom.clipboardCount.textContent = entries.length;
        if (entries.length === 0) {
            dom.clipboardTbody.innerHTML = '<tr class="empty-row"><td colspan="4">No clipboard events</td></tr>';
            return;
        }
        dom.clipboardTbody.innerHTML = entries.map(e => `
            <tr>
                <td><span style="color:var(--pink)">${escHtml(e.content_type || '—')}</span></td>
                <td title="${escHtml(e.content_preview || '')}">${truncate(e.content_preview || '—', 45)}</td>
                <td>${escHtml(e.source_app || '—')}</td>
                <td>${formatTimestamp(e.timestamp)}</td>
            </tr>
        `).join('');
    }

    function renderFileEvents(events) {
        dom.filesCount.textContent = events.length;
        if (events.length === 0) {
            dom.filesTbody.innerHTML = '<tr class="empty-row"><td colspan="4">No file events</td></tr>';
            return;
        }
        dom.filesTbody.innerHTML = events.map(e => {
            const actionColors = {
                'created': 'var(--green)', 'deleted': 'var(--red)',
                'modified': 'var(--amber)', 'renamed_to': 'var(--blue)',
                'renamed_from': 'var(--text-tertiary)',
            };
            const color = actionColors[e.action] || 'var(--text-secondary)';
            return `
            <tr>
                <td><span style="color:${color};font-weight:600">${escHtml(e.action || '—')}</span></td>
                <td title="${escHtml(e.file_path || '')}">${truncate(e.file_path || '—', 45)}</td>
                <td>${escHtml(e.process_name || '—')}</td>
                <td>${formatTimestamp(e.timestamp)}</td>
            </tr>
            `;
        }).join('');
    }

    // ─── WebJail Controls ───────────────────────────────────────

    dom.webjailApply.addEventListener('click', async () => {
        const enabled = dom.webjailToggle.checked;
        const domains = dom.webjailDomains.value
            .split('\n')
            .map(d => d.trim())
            .filter(d => d.length > 0);

        try {
            await api('/api/webjail/toggle', {
                method: 'POST',
                body: JSON.stringify({ enabled, domains }),
            });
        } catch (err) {
            console.error('WebJail toggle failed:', err);
        }
    });

    // ─── Alert Acknowledgment ───────────────────────────────────

    window.ackAlert = async function(alertId) {
        try {
            await api(`/api/alerts/${alertId}/ack`, { method: 'POST' });
            fetchAllData();
        } catch (err) {
            console.error('Alert ack failed:', err);
        }
    };

    // ─── Utilities ──────────────────────────────────────────────

    function escHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    function truncate(str, len) {
        return str.length > len ? str.substring(0, len) + '…' : str;
    }

    function formatDuration(seconds) {
        if (seconds < 1) return '<1s';
        if (seconds < 60) return `${Math.round(seconds)}s`;
        if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`;
        const h = Math.floor(seconds / 3600);
        const m = Math.floor((seconds % 3600) / 60);
        return `${h}h ${m}m`;
    }

    function formatTimestamp(ts) {
        if (!ts) return '—';
        const d = new Date(ts * 1000);
        return d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    }

    function formatUptime(seconds) {
        if (seconds < 60) return `${Math.round(seconds)}s`;
        if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
        const h = Math.floor(seconds / 3600);
        const m = Math.floor((seconds % 3600) / 60);
        return `${h}h ${m}m`;
    }

    // ─── Sidebar Navigation & Scroll Spy ────────────────────────
    const navItems = document.querySelectorAll('.nav-item');
    
    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const target = document.querySelector(item.getAttribute('href'));
            if (target) {
                target.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
        });
    });

    // Scroll Spy to update active state on scroll
    const observerOptions = {
        root: null,
        rootMargin: '-10% 0px -80% 0px', // Triggers when section hits top of viewport
        threshold: 0
    };

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                navItems.forEach(n => n.classList.remove('active'));
                const activeNav = document.querySelector(`.nav-item[href="#${entry.target.id}"]`);
                if (activeNav) {
                    activeNav.classList.add('active');
                }
            }
        });
    }, observerOptions);

    document.querySelectorAll('section.card').forEach(section => {
        observer.observe(section);
    });

    // ─── Initialize ─────────────────────────────────────────────
    checkAuthState();

})();
