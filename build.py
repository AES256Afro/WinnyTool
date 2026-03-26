#!/usr/bin/env python3
"""
WinnyTool Build Script
Automates PyInstaller packaging into a standalone .exe
"""

import subprocess
import sys
import os


def ensure_pyinstaller():
    """Install PyInstaller if it is not already available."""
    try:
        import PyInstaller  # noqa: F401
        print("PyInstaller is already installed.")
    except ImportError:
        print("Installing PyInstaller...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller>=6.0"])
        print("PyInstaller installed successfully.")


def build():
    """Run PyInstaller to produce the WinnyTool executable."""
    project_root = os.path.dirname(os.path.abspath(__file__))
    os.chdir(project_root)

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--windowed",
        "--icon=assets/winnytool.ico",
        "--name=WinnyTool",
        "--add-data", "data;data",
        "--add-data", "assets;assets",
        "winnytool.py",
    ]

    print("Running PyInstaller with command:")
    print("  " + " ".join(cmd))
    print()

    subprocess.check_call(cmd)

    output_path = os.path.join(project_root, "dist", "WinnyTool.exe")
    print()
    print("Build complete!")
    print(f"Output: {output_path}")
    return output_path


if __name__ == "__main__":
    ensure_pyinstaller()
    build()
