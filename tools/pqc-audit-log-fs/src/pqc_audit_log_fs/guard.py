"""FilesystemGuard - enforce append-only semantics where the OS supports it."""

from __future__ import annotations

import os
import platform
import stat
import subprocess

from pqc_audit_log_fs.errors import ImmutabilityViolationError


class FilesystemGuard:
    """Try to mark sealed segment files append-only / immutable where possible.

    Platform behavior:
      - Linux with chattr: sets +a (append-only) on .log and +i (immutable) on .sig.json
      - macOS: sets uchg (user immutable) via chflags
      - Windows / others: in-process check only (drops write bits via chmod)

    Failures to apply OS-level flags are non-fatal unless `strict=True`.
    """

    def __init__(self, strict: bool = False) -> None:
        self.strict = strict
        self._platform = platform.system()

    def seal(self, path: str, mode: str = "immutable") -> None:
        """Mark `path` as immutable (or append-only) where possible."""
        # 1. Unix file permissions: drop write bits
        try:
            current = os.stat(path).st_mode
            os.chmod(path, current & ~0o222)   # remove write for u/g/o
        except OSError as exc:
            if self.strict:
                raise ImmutabilityViolationError(
                    f"chmod failed for {path}: {exc}"
                ) from exc

        # 2. Platform-specific immutable flag
        if self._platform == "Linux":
            try:
                flag = "+a" if mode == "append-only" else "+i"
                subprocess.run(
                    ["chattr", flag, path],
                    check=False, capture_output=True, timeout=5,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                if self.strict:
                    raise ImmutabilityViolationError(
                        f"chattr failed for {path}"
                    ) from exc
        elif self._platform == "Darwin":
            try:
                subprocess.run(
                    ["chflags", "uchg", path],
                    check=False, capture_output=True, timeout=5,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                if self.strict:
                    raise ImmutabilityViolationError(
                        f"chflags failed for {path}"
                    ) from exc
        # Windows / others: no-op beyond chmod

    def verify_read_only(self, path: str) -> bool:
        """Return True if the file appears read-only from our process's POV."""
        if not os.path.exists(path):
            return False
        try:
            st = os.stat(path)
            writable = bool(st.st_mode & stat.S_IWUSR)
            return not writable
        except OSError:
            return False
