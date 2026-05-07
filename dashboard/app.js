        /**
         * Shadow Guardian — Enterprise Command Center
         * Handles auth flow, data polling, and UI rendering.
         * Architecture refined for Cupertino Enterprise UI.
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
                navAlertCount: $('#nav-alert-count'),
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
                        dom.setupError.textContent = data.error || 'System initialization failed';
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
                        dom.loginError.textContent = data.error || 'Authentication denied';
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

                    if (appsResp.status === 'fulfilled' && appsResp.value.ok) renderApps(appsResp.value.data.data || []);
                    if (sessionsResp.status === 'fulfilled' && sessionsResp.value.ok) renderSessions(sessionsResp.value.data.data || []);
                    if (alertsResp.status === 'fulfilled' && alertsResp.value.ok) renderAlerts(alertsResp.value.data.data || []);
                    if (statusResp.status === 'fulfilled' && statusResp.value.ok) renderStatus(statusResp.value.data);
                    if (browserResp.status === 'fulfilled' && browserResp.value.ok) renderBrowserHistory(browserResp.value.data.data || []);
                    if (windowsResp.status === 'fulfilled' && windowsResp.value.ok) renderAllWindows(windowsResp.value.data.data || []);
                    if (usbResp.status === 'fulfilled' && usbResp.value.ok) renderUSBEvents(usbResp.value.data.data || []);
                    if (clipboardResp.status === 'fulfilled' && clipboardResp.value.ok) renderClipboardLog(clipboardResp.value.data.data || []);
                    if (filesResp.status === 'fulfilled' && filesResp.value.ok) renderFileEvents(filesResp.value.data.data || []);
                    
                } catch (err) {
                    setConnectionStatus('offline');
                }
            }

            // ─── Renderers ──────────────────────────────────────────────

            function setConnectionStatus(status) {
                isConnected = status === 'online';
                const label = status === 'online' ? 'System Active' : status === 'offline' ? 'Disconnected' : 'Connecting';
                dom.connectionStatus.textContent = label;
                dom.connectionStatus.className = `status-pill ${status}`;
            }

            // ─── App Icon Config (Muted Premium Palette) ────────────────
            const APP_ICONS = {
                'brave.exe':     { color: '#B34A2E', label: 'B', name: 'Brave' },
                'chrome.exe':    { color: '#2B5A9E', label: 'C', name: 'Google Chrome' },
                'msedge.exe':    { color: '#1B548A', label: 'E', name: 'Microsoft Edge' },
                'firefox.exe':   { color: '#B85834', label: 'F', name: 'Firefox' },
                'spotify.exe':   { color: '#1C803E', label: 'S', name: 'Spotify' },
                'discord.exe':   { color: '#444C9E', label: 'D', name: 'Discord' },
                'code.exe':      { color: '#1C5B8F', label: 'VS', name: 'VS Code' },
                'explorer.exe':  { color: '#A88222', label: 'E', name: 'File Explorer' },
                'notepad.exe':   { color: '#4A4E54', label: 'N', name: 'Notepad' },
                'cmd.exe':       { color: '#121212', label: '>', name: 'Command Prompt' },
                'powershell.exe':{ color: '#091C3B', label: 'PS', name: 'PowerShell' },
                'windowsterminal.exe': { color: '#333333', label: 'WT', name: 'Windows Terminal' },
                'teams.exe':     { color: '#494A7A', label: 'T', name: 'Microsoft Teams' },
                'slack.exe':     { color: '#381638', label: 'S', name: 'Slack' },
                'outlook.exe':   { color: '#1B548A', label: 'O', name: 'Outlook' },
                'winword.exe':   { color: '#223E6B', label: 'W', name: 'Microsoft Word' },
                'excel.exe':     { color: '#194D31', label: 'X', name: 'Microsoft Excel' },
                'vlc.exe':       { color: '#B86A1A', label: 'V', name: 'VLC' },
                'taskmgr.exe':   { color: '#2B5A9E', label: 'TM', name: 'Task Manager' },
            };

            function getAppIcon(processName) {
                const key = (processName || '').toLowerCase();
                if (APP_ICONS[key]) return APP_ICONS[key];
                let hash = 0;
                for (let i = 0; i < key.length; i++) hash = key.charCodeAt(i) + ((hash << 5) - hash);
                const hue = Math.abs(hash) % 360;
                return {
                    color: `hsl(${hue}, 40%, 35%)`, // Muted saturation and lightness
                    label: (processName || '?')[0].toUpperCase(),
                    name: processName ? processName.replace(/\.exe$/i, '') : 'Unknown',
                };
            }

            const expandedApps = new Set();

            function renderApps(apps) {
                dom.appsCount.textContent = apps.length;

                if (apps.length === 0) {
                    dom.appsTree.innerHTML = '<div class="empty-message">Awaiting application telemetry</div>';
                    return;
                }

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
                        <div class="child-row" title="${escHtml(w.exe_path || '')}">
                            ${w.is_foreground ? '<div class="indicator-dot"></div>' : ''}
                            <span class="child-title">${escHtml(w.window_title || 'Untitled')}</span>
                            <span class="child-pid">PID ${w.pid || '?'}</span>
                        </div>
                    `).join('');

                    return `
                    <div class="process-group${expandClass}" data-process="${escHtml(group.process_name)}">
                        <div class="process-header${fgClass}">
                            <div class="app-icon-sys" style="background:${icon.color}">${icon.label}</div>
                            <div class="process-info">
                                <div class="process-name">${escHtml(icon.name)}</div>
                                <div class="process-meta">${escHtml(group.process_name)} • ${formatDuration(group.totalDuration)} • PIDs: ${uniquePids.join(', ')}</div>
                            </div>
                            <div class="process-stats">
                                <span class="window-count">${group.windows.length}</span>
                                <svg class="expand-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"/></svg>
                            </div>
                        </div>
                        <div class="process-children">
                            ${childRows}
                        </div>
                    </div>
                    `;
                }).join('');
            }

            dom.appsTree.addEventListener('click', function(e) {
                const header = e.target.closest('.process-header');
                if (!header) return;
                const group = header.closest('.process-group');
                if (!group) return;
                const processName = group.dataset.process;
                group.classList.toggle('expanded');
                if (group.classList.contains('expanded')) expandedApps.add(processName);
                else expandedApps.delete(processName);
            });

            function renderSessions(sessions) {
                dom.sessionsCount.textContent = sessions.length;
                if (sessions.length === 0) {
                    dom.sessionTimeline.innerHTML = '<div class="empty-message">No session events logged</div>';
                    return;
                }
                dom.sessionTimeline.innerHTML = sessions.map(s => {
                    let typeClass = '';
                    if(s.event_type === 'lock' || s.event_type === 'logout') typeClass = 't-lock';
                    if(s.event_type === 'unlock' || s.event_type === 'login') typeClass = 't-unlock';
                    
                    return `
                    <div class="time-node ${typeClass}">
                        <div class="t-title">${escHtml(s.event_type || 'Unknown')}</div>
                        <div class="t-meta">${formatTimestamp(s.timestamp)} • User: ${escHtml(s.username || '—')}</div>
                    </div>
                `}).join('');
            }

            function renderAlerts(alerts) {
                const unacked = alerts.filter(a => !a.acknowledged);
                dom.alertsCount.textContent = unacked.length;
                
                if(unacked.length > 0) {
                    dom.navAlertCount.textContent = unacked.length;
                    dom.navAlertCount.classList.remove('hidden');
                } else {
                    dom.navAlertCount.classList.add('hidden');
                }

                if (alerts.length === 0) {
                    dom.alertsList.innerHTML = '<div class="empty-message">System integrity verified. Zero anomalies.</div>';
                    return;
                }

                dom.alertsList.innerHTML = alerts.map(a => {
                    let sevClass = 'sev-low';
                    if(a.severity === 'warning') sevClass = 'sev-med';
                    if(a.severity === 'critical') sevClass = 'sev-high';

                    return `
                    <div class="alert-card ${sevClass}" data-id="${a.id}">
                        <div class="alert-body">
                            <div class="alert-msg">${escHtml(a.message || 'Security Event')}</div>
                            <div class="alert-time">${formatTimestamp(a.timestamp)} • ${escHtml(a.alert_type || '')}</div>
                        </div>
                        ${!a.acknowledged ? `<button class="btn-ack" onclick="ackAlert(${a.id})">Acknowledge</button>` : ''}
                    </div>
                `}).join('');
            }

            function renderStatus(status) {
                if (status.cpu_percent !== undefined) dom.statCpu.textContent = `${status.cpu_percent.toFixed(1)}%`;
                if (status.memory_mb !== undefined) dom.statMem.textContent = `${status.memory_mb.toFixed(0)} MB`;
                if (status.uptime !== undefined) dom.statUptime.textContent = formatUptime(status.uptime);

                if (status.webjail) {
                    const wjEnabled = status.webjail.enabled;
                    
                    if (!window.webjailDirty) {
                        dom.webjailToggle.checked = wjEnabled;
                    }
                    
                    dom.webjailStatus.textContent = wjEnabled ? 'Active' : 'Inactive';
                    dom.webjailStatus.className = `status-pill ${wjEnabled ? 'active' : 'off'}`;

                    if (status.webjail.blocked_domains && status.webjail.blocked_domains.length > 0) {
                        if (!dom.webjailDomains.value.trim()) {
                            dom.webjailDomains.value = status.webjail.blocked_domains.join('\n');
                        }
                    }
                }
            }

            function renderBrowserHistory(entries) {
                dom.browserCount.textContent = entries.length;
                if (entries.length === 0) {
                    dom.browserTbody.innerHTML = '<tr class="placeholder"><td colspan="4">No browser traffic recorded</td></tr>';
                    return;
                }
                dom.browserTbody.innerHTML = entries.map(e => `
                    <tr>
                        <td><span style="color:var(--accent-purple);font-weight:500">${escHtml(e.browser || '—')}</span></td>
                        <td title="${escHtml(e.title || '')}">${truncate(e.title || '—', 35)}</td>
                        <td title="${escHtml(e.url || '')}"><span style="color:var(--text-secondary);">${truncate(e.url || '—', 40)}</span></td>
                        <td><span style="color:var(--text-tertiary);font-family:var(--font-mono);font-size:12px;">${formatTimestamp(e.visit_time || e.timestamp)}</span></td>
                    </tr>
                `).join('');
            }

            function renderAllWindows(windows) {
                dom.windowsCount.textContent = windows.length;
                if (windows.length === 0) {
                    dom.windowsTbody.innerHTML = '<tr class="placeholder"><td colspan="5">No active windows</td></tr>';
                    return;
                }
                dom.windowsTbody.innerHTML = windows.map(w => `
                    <tr${w.is_foreground ? ' style="background:var(--accent-blue-dim)"' : ''}>
                        <td>${escHtml(w.process_name || '—')}</td>
                        <td title="${escHtml(w.window_title || '')}">${truncate(w.window_title || '—', 35)}</td>
                        <td><span style="color:var(--text-secondary)">${escHtml(w.tab_title || '—')}</span></td>
                        <td style="font-family:var(--font-mono);font-size:12px;color:var(--text-tertiary)">${w.pid || '—'}</td>
                        <td>${w.is_foreground ? '<span style="color:var(--accent-blue);font-weight:600;font-size:12px;">Active</span>' : ''}</td>
                    </tr>
                `).join('');
            }

            function renderUSBEvents(events) {
                dom.usbCount.textContent = events.length;
                if (events.length === 0) {
                    dom.usbTbody.innerHTML = '<tr class="placeholder"><td colspan="4">No peripheral activity</td></tr>';
                    return;
                }
                dom.usbTbody.innerHTML = events.map(e => {
                    const actionColor = e.action === 'connected' ? 'var(--accent-green)' : 'var(--accent-orange)';
                    return `
                    <tr>
                        <td style="font-weight:500;">${escHtml(e.device_name || '—')}</td>
                        <td><span style="color:${actionColor};font-weight:600;font-size:12px;text-transform:uppercase;">${escHtml(e.action || '—')}</span></td>
                        <td title="${escHtml(e.device_id || '')}" style="color:var(--text-secondary);">${truncate(e.device_id || '—', 30)}</td>
                        <td style="font-family:var(--font-mono);font-size:12px;color:var(--text-tertiary);">${formatTimestamp(e.timestamp)}</td>
                    </tr>
                    `;
                }).join('');
            }

            function renderClipboardLog(entries) {
                // Ensure we only show maximum of 3 items
                const slicedEntries = entries.slice(0, 3);
                dom.clipboardCount.textContent = slicedEntries.length;
                if (slicedEntries.length === 0) {
                    dom.clipboardTbody.innerHTML = '<tr class="placeholder"><td colspan="3">Buffer empty</td></tr>';
                    return;
                }
                dom.clipboardTbody.innerHTML = slicedEntries.map(e => `
                    <tr>
                        <td><span style="color:var(--text-secondary);font-weight:500">${escHtml(e.content_type || '—')}</span></td>
                        <td><span style="color:var(--text-secondary);">${escHtml(e.source_app || '—')}</span></td>
                        <td style="font-family:var(--font-mono);font-size:12px;color:var(--text-tertiary);">${formatTimestamp(e.timestamp)}</td>
                    </tr>
                `).join('');
            }

            function renderFileEvents(events) {
                dom.filesCount.textContent = events.length;
                if (events.length === 0) {
                    dom.filesTbody.innerHTML = '<tr class="placeholder"><td colspan="4">No I/O operations recorded</td></tr>';
                    return;
                }
                dom.filesTbody.innerHTML = events.map(e => {
                    const actionColors = {
                        'created': 'var(--accent-green)', 'deleted': 'var(--accent-red)',
                        'modified': 'var(--accent-orange)', 'renamed_to': 'var(--accent-blue)',
                    };
                    const color = actionColors[e.action] || 'var(--text-secondary)';
                    return `
                    <tr>
                        <td><span style="color:${color};font-weight:600;font-size:12px;text-transform:uppercase;">${escHtml(e.action || '—')}</span></td>
                        <td title="${escHtml(e.file_path || '')}">${truncate(e.file_path || '—', 55)}</td>
                        <td><span style="color:var(--text-secondary);">${escHtml(e.process_name || '—')}</span></td>
                        <td style="font-family:var(--font-mono);font-size:12px;color:var(--text-tertiary);">${formatTimestamp(e.timestamp)}</td>
                    </tr>
                    `;
                }).join('');
            }

            // ─── Controls ───────────────────────────────────────────────

            dom.webjailToggle.addEventListener('change', () => {
                window.webjailDirty = true;
            });
            
            dom.webjailDomains.addEventListener('input', () => {
                window.webjailDirty = true;
            });

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
                    window.webjailDirty = false;
                    dom.webjailApply.textContent = 'Deployed';
                    setTimeout(()=> { dom.webjailApply.textContent = 'Deploy Ruleset'; }, 2000);
                } catch (err) {
                    console.error('Policy deployment failed:', err);
                }
            });

            window.ackAlert = async function(alertId) {
                try {
                    await api(`/api/alerts/${alertId}/ack`, { method: 'POST' });
                    fetchAllData();
                } catch (err) {
                    console.error('Acknowledgment failed:', err);
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

            // ─── Navigation Observer ────────────────────────────────────
            const navItems = document.querySelectorAll('.nav-item');
            
            navItems.forEach(item => {
                item.addEventListener('click', (e) => {
                    e.preventDefault();
                    const target = document.querySelector(item.getAttribute('href'));
                    if (target) target.scrollIntoView({ behavior: 'smooth', block: 'start' });
                });
            });

            const observerOptions = { root: null, rootMargin: '-10% 0px -80% 0px', threshold: 0 };
            const observer = new IntersectionObserver((entries) => {
                entries.forEach(entry => {
                    if (entry.isIntersecting) {
                        navItems.forEach(n => n.classList.remove('active'));
                        const activeNav = document.querySelector(`.nav-item[href="#${entry.target.id}"]`);
                        if (activeNav) activeNav.classList.add('active');
                    }
                });
            }, observerOptions);

            document.querySelectorAll('section.panel').forEach(section => observer.observe(section));

            // ─── Initialize ─────────────────────────────────────────────
            checkAuthState();

        })();
