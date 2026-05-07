"""
Shadow Guardian — Elevation & Auto-Start Utilities

Handles:
  - Admin privilege detection
  - One-shot UAC self-elevation
  - Scheduled Task creation for silent elevated auto-start
"""

import os
import sys
import ctypes
import subprocess
from pathlib import Path

from utils.logger import get_logger

logger = get_logger("utils.elevation")

TASK_NAME = "ShadowGuardian"


def is_admin() -> bool:
    """Check if the current process has administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def self_elevate(args: list[str] | None = None) -> bool:
    """
    Re-launch the current process with administrator elevation via UAC.

    Returns True if the elevated process was launched (caller should exit).
    Returns False if elevation failed or was cancelled by the user.
    """
    try:
        exe = sys.executable
        if args is None:
            args = sys.argv[1:]

        params = " ".join(f'"{a}"' if " " in a else a for a in args)

        logger.info(f"Requesting admin elevation: {exe} {params}")
        result = ctypes.windll.shell32.ShellExecuteW(
            None,           # parent window
            "runas",        # verb — triggers UAC
            exe,            # executable
            params,         # arguments
            None,           # working directory (inherit)
            1,              # SW_SHOWNORMAL
        )
        # ShellExecuteW returns > 32 on success
        return result > 32
    except Exception as e:
        logger.error(f"Self-elevation failed: {e}")
        return False


def is_autostart_registered() -> bool:
    """Check if the ShadowGuardian scheduled task exists."""
    try:
        result = subprocess.run(
            ["schtasks", "/Query", "/TN", TASK_NAME],
            capture_output=True,
            creationflags=0x08000000,  # CREATE_NO_WINDOW
        )
        return result.returncode == 0
    except Exception:
        return False


def register_autostart(exe_path: str | None = None) -> bool:
    """
    Create a Windows Scheduled Task that runs ShadowGuardian at logon
    with highest privileges (admin, NO UAC prompt).

    Must be called from an elevated (admin) process.
    """
    if not is_admin():
        logger.error("Cannot register auto-start without admin privileges")
        return False

    if exe_path is None:
        exe_path = sys.executable

    exe_path = str(Path(exe_path).resolve())

    try:
        # Remove existing task first (if any)
        subprocess.run(
            ["schtasks", "/Delete", "/TN", TASK_NAME, "/F"],
            capture_output=True,
            creationflags=0x08000000,
        )

        # Create new task via XML to disable battery restrictions
        import tempfile
        xml_content = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>ShadowGuardian</Author>
    <URI>\\{TASK_NAME}</URI>
  </RegistrationInfo>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
  </Settings>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <Delay>PT5S</Delay>
    </LogonTrigger>
  </Triggers>
  <Actions Context="Author">
    <Exec>
      <Command>"{exe_path}"</Command>
    </Exec>
  </Actions>
</Task>"""

        with tempfile.NamedTemporaryFile("w", suffix=".xml", encoding="utf-16", delete=False) as f:
            f.write(xml_content)
            temp_xml_path = f.name

        try:
            result = subprocess.run(
                ["schtasks", "/Create", "/TN", TASK_NAME, "/XML", temp_xml_path, "/F"],
                capture_output=True,
                text=True,
                creationflags=0x08000000,
            )

            if result.returncode == 0:
                logger.info(f"Auto-start scheduled task created: {exe_path}")
                return True
            else:
                logger.error(f"schtasks failed: {result.stderr}")
                return False
        finally:
            try:
                os.remove(temp_xml_path)
            except Exception:
                pass
    except Exception as e:
        logger.error(f"Failed to register auto-start: {e}")
        return False


def unregister_autostart() -> bool:
    """Remove the ShadowGuardian scheduled task."""
    if not is_admin():
        logger.error("Cannot unregister auto-start without admin privileges")
        return False

    try:
        result = subprocess.run(
            ["schtasks", "/Delete", "/TN", TASK_NAME, "/F"],
            capture_output=True,
            creationflags=0x08000000,
        )
        if result.returncode == 0:
            logger.info("Auto-start scheduled task removed")
            return True
        return False
    except Exception as e:
        logger.error(f"Failed to unregister auto-start: {e}")
        return False
