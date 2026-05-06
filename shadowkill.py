"""
Shadow Guardian — ShadowKill

Custom terminal command to kill the ShadowGuardian process.
Usage: python shadowkill.py

Sends graceful IPC shutdown first, then force-kills if needed.
"""

import os
import sys
import time
import signal
from pathlib import Path

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)


def find_shadow_pids() -> list[int]:
    """Find ShadowGuardian process IDs."""
    pids = []
    
    # Check PID file first
    try:
        from utils.paths import get_app_data_dir
        pid_file = get_app_data_dir() / "agent.pid"
        if pid_file.exists():
            pid = int(pid_file.read_text().strip())
            pids.append(pid)
    except Exception:
        pass

    # Also scan running processes
    try:
        import psutil
        for proc in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                name = (proc.info.get("name") or "").lower()
                
                # Match by process name directly
                if name in ("shadowguardian.exe", "winservicehelper.exe"):
                    if proc.info["pid"] != os.getpid():
                        pids.append(proc.info["pid"])
                    continue

                # Match Python processes running shadowguardian components
                cmdline = proc.info.get("cmdline") or []
                if name in ("python.exe", "pythonw.exe", "python3.11.exe"):
                    for arg in cmdline:
                        if any(x in arg for x in ["shadowguardian.py", "run_watchdog.py", "run_agent.py", "run_api.py"]):
                            pids.append(proc.info["pid"])
                            break
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except ImportError:
        pass

    return list(set(pids))


def graceful_shutdown() -> bool:
    """Try graceful shutdown via IPC."""
    try:
        from core.ipc import IPCClient
        client = IPCClient(timeout_ms=3000)
        response = client.send_command({"command": "SHUTDOWN"})
        return response.get("status") == "ok"
    except Exception:
        return False


def force_kill(pids: list[int]) -> int:
    """Force kill processes by PID."""
    killed = 0
    try:
        import psutil
        for pid in pids:
            try:
                proc = psutil.Process(pid)
                proc.kill()
                killed += 1
                print(f"  Killed PID {pid} ({proc.name()})")
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                print(f"  Cannot kill PID {pid}: {e}")
    except ImportError:
        # Fallback: use os.kill
        for pid in pids:
            try:
                os.kill(pid, signal.SIGTERM)
                killed += 1
                print(f"  Sent SIGTERM to PID {pid}")
            except Exception as e:
                print(f"  Cannot kill PID {pid}: {e}")
    return killed


def cleanup_files():
    """Clean up PID and port files across all possible directories."""
    try:
        from utils.paths import get_app_data_dir
        
        # Check both local project root and AppData (for compiled versions)
        dirs_to_clean = [get_app_data_dir()]
        
        local_app_data = os.environ.get('LOCALAPPDATA', '')
        if local_app_data:
            appdata_dir = Path(local_app_data) / "ShadowGuardian"
            if appdata_dir.exists() and appdata_dir not in dirs_to_clean:
                dirs_to_clean.append(appdata_dir)

        for data_dir in dirs_to_clean:
            for filename in ["agent.pid", "api_port.txt"]:
                f = data_dir / filename
                if f.exists():
                    f.unlink()
                    print(f"  Cleaned: {f}")

            # Clean breadcrumb files
            for txt_file in data_dir.glob("sg_port_*.txt"):
                txt_file.unlink()
                print(f"  Cleaned: {txt_file}")
    except Exception as e:
        print(f"  Cleanup error: {e}")


def main():
    print()
    print("+======================================+")
    print("|       SHADOW GUARDIAN -- KILL         |")
    print("+======================================+")
    print()

    pids = find_shadow_pids()

    if not pids:
        print("  No ShadowGuardian processes found.")
        print("  System is clean.")
        cleanup_files()
        return

    print(f"  Found {len(pids)} ShadowGuardian process(es): {pids}")
    print()

    # Try graceful shutdown first
    print("  [1/3] Attempting graceful shutdown via IPC...")
    if graceful_shutdown():
        print("        Shutdown command sent. Waiting 3s...")
        time.sleep(3)
        
        remaining = [p for p in pids if _is_running(p)]
        if not remaining:
            print("        Graceful shutdown successful.")
            cleanup_files()
            print()
            print("  Shadow Guardian terminated.")
            return
        print(f"        {len(remaining)} process(es) still running.")
    else:
        print("        IPC unavailable — proceeding to force kill.")

    # Force kill
    print("  [2/3] Force killing processes...")
    killed = force_kill(pids)

    # Verify
    time.sleep(1)
    remaining = [p for p in pids if _is_running(p)]
    if remaining:
        print(f"  [3/3] WARNING: {len(remaining)} process(es) survived. Try running as admin.")
    else:
        print(f"  [3/3] All processes terminated. ({killed} killed)")

    cleanup_files()
    print()
    print("  Shadow Guardian terminated.")


def _is_running(pid: int) -> bool:
    """Check if a PID is still running."""
    try:
        import psutil
        return psutil.pid_exists(pid)
    except ImportError:
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False


if __name__ == "__main__":
    main()
