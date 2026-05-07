"""
Shadow Guardian — Build Script

Builds standalone Windows executables using PyInstaller
and optionally compiles the Inno Setup installer.
"""

import subprocess
import sys
import os
import shutil
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent
DIST_DIR = PROJECT_ROOT / "dist"
BUILD_DIR = PROJECT_ROOT / "build"
OUTPUT_DIR = DIST_DIR / "ShadowGuardian"

# Files to include alongside the executable
DATA_FILES = [
    ("config.json", "."),
    ("dashboard/index.html", "dashboard"),
    ("dashboard/style.css", "dashboard"),
    ("dashboard/app.js", "dashboard"),
]

# Hidden imports that PyInstaller might miss
HIDDEN_IMPORTS = [
    "agent",
    "agent.core",
    "agent.window_tracker",
    "agent.session_tracker",
    "agent.process_monitor",
    "agent.alert_engine",
    "agent.tray",
    "watchdog",
    "watchdog.supervisor",
    "api",
    "api.server",
    "core",
    "core.ipc",
    "core.event_queue",
    "core.webjail",
    "webjail_ext",
    "db",
    "db.database",
    "sync",
    "sync.cloud_sync",
    "utils",
    "utils.config",
    "utils.logger",
    "utils.crypto",
    "utils.single_instance",
    "utils.secrets_store",
    "utils.paths",
    "utils.elevation",
    "flask",
    "flask.json",
    "waitress",
    "psutil",
    "pystray",
    "PIL",
    "PIL.Image",
    "PIL.ImageDraw",
    "win32pipe",
    "win32file",
    "win32api",
    "win32gui",
    "win32ts",
    "pywintypes",
    "cryptography",
    "cryptography.hazmat.primitives.ciphers.aead",
    "cryptography.hazmat.primitives.kdf.pbkdf2",
]


def clean():
    """Clean previous build artifacts."""
    print(">>> Cleaning previous builds...")
    for d in [BUILD_DIR, DIST_DIR]:
        if d.exists():
            shutil.rmtree(d)
    # Remove .spec if exists
    spec = PROJECT_ROOT / "ShadowGuardian.spec"
    if spec.exists():
        spec.unlink()


def build_exe():
    """Build the standalone executable with PyInstaller."""
    print(">>> Building ShadowGuardian.exe...")

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--name=ShadowGuardian",
        "--onedir",                  # One directory (faster startup than onefile)
        "--windowed",                # No console window (tray app)
        "--noconfirm",
        f"--icon={PROJECT_ROOT}/assets/icon.ico",
        f"--distpath={DIST_DIR}",
        f"--workpath={BUILD_DIR}",
        "--clean",

        # Icon (will be generated if not exists)
        # "--icon=assets/icon.ico",
    ]

    # Add data files
    for src, dest in DATA_FILES:
        src_path = PROJECT_ROOT / src
        if src_path.exists():
            sep = ";" if sys.platform == "win32" else ":"
            cmd.append(f"--add-data={src_path}{sep}{dest}")

    # Add hidden imports
    for imp in HIDDEN_IMPORTS:
        cmd.append(f"--hidden-import={imp}")

    # Add paths for module discovery
    cmd.append(f"--paths={PROJECT_ROOT}")

    # Entry point
    cmd.append(str(PROJECT_ROOT / "shadowguardian.py"))

    print(f"  Command: {' '.join(cmd[:5])}...")

    result = subprocess.run(cmd, cwd=str(PROJECT_ROOT))
    if result.returncode != 0:
        print("[FAIL] Build failed!")
        sys.exit(1)

    print("[OK] Build successful!")

    # Copy additional files that need to be writable
    _copy_runtime_files()


def _copy_runtime_files():
    """Copy files that need to be alongside the exe at runtime."""
    print(">>> Copying runtime files...")

    output = OUTPUT_DIR

    # Config file (writable copy)
    src_config = PROJECT_ROOT / "config.json"
    dst_config = output / "config.json"
    if not dst_config.exists():
        shutil.copy2(str(src_config), str(dst_config))

    # Dashboard files
    dash_dir = output / "dashboard"
    dash_dir.mkdir(exist_ok=True)
    for f in ["index.html", "style.css", "app.js"]:
        src = PROJECT_ROOT / "dashboard" / f
        if src.exists():
            shutil.copy2(str(src), str(dash_dir / f))

    # Create logs directory
    (output / "logs").mkdir(exist_ok=True)

    # Create README
    readme_src = PROJECT_ROOT / "README.md"
    if readme_src.exists():
        shutil.copy2(str(readme_src), str(output / "README.md"))

    print("  [OK] Runtime files copied")


def build_installer():
    """Compile the Inno Setup installer script."""
    print(">>> Building installer...")

    iss_file = PROJECT_ROOT / "installer.iss"
    if not iss_file.exists():
        print("  [FAIL] installer.iss not found")
        return False

    # Find Inno Setup compiler
    inno_paths = [
        r"C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
        r"C:\Program Files\Inno Setup 6\ISCC.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe"),
    ]

    iscc = None
    for p in inno_paths:
        if os.path.exists(p):
            iscc = p
            break

    if not iscc:
        print("  [WARN] Inno Setup not found — skipping installer build")
        print("     Download from: https://jrsoftware.org/isdl.php")
        return False

    result = subprocess.run([iscc, str(iss_file)], cwd=str(PROJECT_ROOT))
    if result.returncode == 0:
        print("[OK] Installer built successfully!")
        return True
    else:
        print("[FAIL] Installer build failed!")
        return False


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Build Shadow Guardian")
    parser.add_argument("--clean", action="store_true", help="Clean only")
    parser.add_argument("--no-installer", action="store_true", help="Skip installer")
    parser.add_argument("--installer-only", action="store_true", help="Build installer only")
    args = parser.parse_args()

    print("=" * 55)
    print("  Shadow Guardian Build System")
    print("=" * 55)

    if args.clean:
        clean()
        return

    if args.installer_only:
        build_installer()
        return

    clean()
    build_exe()

    if not args.no_installer:
        build_installer()

    print()
    print("=" * 55)
    print("  Build complete!")
    print(f"  Executable: {OUTPUT_DIR / 'ShadowGuardian.exe'}")
    installer = DIST_DIR / "ShadowGuardianSetup.exe"
    if installer.exists():
        print(f"  Installer:  {installer}")
    print("=" * 55)


if __name__ == "__main__":
    main()
