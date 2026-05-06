import os
import sys
from pathlib import Path

def get_app_data_dir() -> Path:
    """
    Get the directory for writable application data.
    Uses LOCALAPPDATA/ShadowGuardian when frozen (installed),
    otherwise uses the project root.
    """
    if getattr(sys, 'frozen', False):
        # Running as PyInstaller executable
        local_app_data = os.environ.get('LOCALAPPDATA', '')
        if local_app_data:
            data_dir = Path(local_app_data) / "ShadowGuardian"
        else:
            # Fallback if LOCALAPPDATA is not set
            data_dir = Path.home() / ".shadowguardian"
    else:
        # Running from source
        data_dir = Path(__file__).parent.parent

    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir
