"""
Single-instance guards for Shadow Guardian processes.

Uses named Windows mutexes so a second agent/API instance fails fast instead
of creating duplicate monitors or binding a second dashboard port.
"""

import ctypes
from typing import Optional


ERROR_ALREADY_EXISTS = 183


class SingleInstance:
    """Named mutex wrapper."""

    def __init__(self, name: str):
        self._name = rf"Local\{name}"
        self._handle: Optional[int] = None

    def acquire(self) -> bool:
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.CreateMutexW(None, False, self._name)
        if not handle:
            return False
        self._handle = handle
        return kernel32.GetLastError() != ERROR_ALREADY_EXISTS

    def release(self) -> None:
        if self._handle:
            ctypes.windll.kernel32.CloseHandle(self._handle)
            self._handle = None

    def __del__(self):
        self.release()
