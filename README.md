#  Shadow Guardian

**Production-grade, event-driven desktop monitoring system for Windows.**

A lightweight, multi-process endpoint monitoring agent that tracks system activity, sessions, and security-relevant events while remaining efficient, transparent, and user-controlled.

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│                  WATCHDOG                        │
│  Supervises agent + API with exponential backoff │
├────────────────────┬────────────────────────────┤
│   CORE AGENT       │    API SERVER (Flask)       │
│  ┌──────────────┐  │   ┌──────────────────┐     │
│  │ Window Hook  │  │   │ /api/apps        │     │
│  │ Session Hook │◄─┼──►│ /api/sessions    │     │
│  │ Process Mon. │  │   │ /api/alerts      │     │
│  │ Alert Engine │ IPC  │ /api/webjail     │     │
│  │ DB Writer    │(pipe)│ /api/status      │     │
│  │ Packet Sniff │  │   └──────────────────┘     │
│  └──────┬───────┘  │           │                 │
│         │          │           │ HTTP             │
│    ┌────▼────┐     │   ┌──────▼──────────┐      │
│    │ SQLite  │     │   │   Dashboard     │      │
│    │ (WAL)   │     │   │  (HTML+JS)      │      │
│    └─────────┘     │   └─────────────────┘      │
└────────────────────┴────────────────────────────┘
```

## Features

- **Event-Driven Window Tracking** — Uses `SetWinEventHook` (zero polling)
- **Session Monitoring** — Login, logout, lock, unlock via `WTSRegisterSessionNotification`
- **Adaptive Process Monitoring** — Polls faster during activity, slower when idle
- **Packet-Level Network Capture** — Scapy + Npcap for production-grade inspection
- **Rule-Based Alert Engine** — Unknown processes, rapid spawning, high connections
- **WebJail** — Domain blocking via hosts file with backup/rollback
- **Named Pipe IPC** — Agent ↔ API communication (no internal HTTP)
- **Cloud Sync** — Supabase with offline-first, compression, AES-256-GCM encryption
- **Auth-Gated Dashboard** — First-run setup wizard, password-protected access
- **Watchdog Supervisor** — Exponential backoff restart (1→2→5→10→30s)
- **Config Hot-Reload** — Change settings without restarting

## Requirements

- **Python 3.10+**
- **Windows 10/11**
- **Npcap** (for packet capture): [https://npcap.com/](https://npcap.com/)

## Quick Start

### 1. Install Dependencies

```bash
cd e:\shadowguardian
pip install -r requirements.txt
```

### 2. Install Npcap (for network monitoring)

Download and install from [npcap.com](https://npcap.com/). Select "Install in WinPcap API-compatible mode".

### 3. Run via Watchdog (Recommended)

```bash
python run_watchdog.py
```

This starts:
- Core Agent (monitoring, DB, IPC)
- API Server (dashboard, REST API)
- Watchdog supervision with auto-restart

### 4. First-Run Setup

On first launch, the dashboard opens in your browser automatically.
- Set a dashboard password (min 6 characters)
- Optionally enable cloud sync with Supabase credentials

### 5. Subsequent Access

Open your browser to the URL shown in the console (e.g., `http://127.0.0.1:XXXXX`).
The port is dynamic and written to `api_port.txt`.

## Manual Start (Individual Components)

```bash
# Terminal 1: Agent
python run_agent.py

# Terminal 2: API Server
python run_api.py
```

## Configuration

Edit `config.json` — changes are hot-reloaded automatically.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `dynamic_port` | bool | `true` | Auto-assign API port |
| `log_level` | string | `"production"` | `"debug"` or `"production"` |
| `batch_write_interval` | int | `3` | DB write interval (seconds) |
| `feature_flags.webjail_enabled` | bool | `false` | Enable WebJail |
| `feature_flags.cloud_sync_enabled` | bool | `false` | Enable Supabase sync |
| `feature_flags.network_monitoring` | bool | `true` | Enable network capture |
| `feature_flags.alert_engine` | bool | `true` | Enable alert rules |
| `sync_interval` | int | `300` | Cloud sync interval (seconds) |
| `adaptive_polling.active_interval` | int | `5` | Poll rate when active |
| `adaptive_polling.idle_interval` | int | `30` | Poll rate when idle |
| `webjail_domains` | array | `[]` | Domains to block |

## WebJail (Admin Required)

To use domain blocking, run with Administrator privileges:

```bash
# Run as Administrator
python run_watchdog.py
```

## Project Structure

```
shadowguardian/
├── agent/
│   ├── core.py              # Main agent orchestrator
│   ├── window_tracker.py    # Foreground window event hook
│   ├── session_tracker.py   # Login/lock/unlock sensor
│   ├── process_monitor.py   # Process + network monitoring
│   └── alert_engine.py      # Rule-based alert system
├── watchdog/
│   └── supervisor.py        # Exponential backoff supervisor
├── api/
│   └── server.py            # Flask API (localhost only)
├── dashboard/
│   ├── index.html           # Dashboard UI
│   ├── style.css            # Dark theme styles
│   └── app.js               # Dashboard logic
├── core/
│   ├── ipc.py               # Named pipe IPC
│   ├── event_queue.py       # Thread-safe event buffer
│   └── webjail.py           # Hosts file blocker
├── db/
│   └── database.py          # SQLite WAL + batch writes
├── sync/
│   └── cloud_sync.py        # Supabase sync worker
├── utils/
│   ├── config.py            # Config manager + hot reload
│   ├── logger.py            # Structured JSON logging
│   └── crypto.py            # AES-256-GCM encryption
├── config.json              # Configuration file
├── requirements.txt         # Python dependencies
├── run_agent.py             # Agent entry point
├── run_watchdog.py          # Watchdog entry point
└── run_api.py               # API entry point
```

## Performance Targets

| Metric | Target | How |
|--------|--------|-----|
| Idle CPU | < 2% | Event-driven hooks, no busy loops |
| Memory | < 80MB | Bounded queues, batch writes |
| Startup | < 1s | Lazy initialization |
| Dashboard load | < 200ms | Minimal JS, no frameworks |

## Security Notes

- **Visible in Task Manager** — no process hiding
- **User-controllable** — all features can be disabled
- **Localhost only** — API never binds to external interfaces
- **Auth-gated** — password required for dashboard access
- **No covert surveillance** — transparent operation

## Logs

Structured JSON logs are in the `logs/` directory:
- `shadowguardian.log` — All events (rotating, 5MB × 5)
- `errors.log` — Errors only (rotating, 2MB × 3)

## License

Private — Internal use only.
