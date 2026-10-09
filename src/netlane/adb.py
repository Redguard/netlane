import logging
import shlex
import subprocess
import tempfile
from typing import Iterable, Optional

from netlane.utils import run_cmd

logger = logging.getLogger(__name__)

DEVICE_TMP_DIR = "/data/local/tmp"


def run(
    serial: Optional[str], args: Iterable[str], check: bool = True
) -> subprocess.CompletedProcess:
    """Runs `adb <args>` against the device with `serial`, or the only connected one."""
    return run_cmd([*_adb(serial), *args], check=check)


def shell(
    serial: Optional[str], cmd: str, check: bool = True
) -> subprocess.CompletedProcess:
    """Runs `cmd` in an unprivileged shell on the device."""
    return run(serial, ["shell", "-n", cmd], check=check)


def run_script(
    serial: Optional[str], elevation: str, content: str, check: bool = True
) -> subprocess.CompletedProcess:
    """Runs `content` from a device temp file as stdin of the root shell `elevation`. An empty `elevation` requires adbd to run as root."""
    tmp = _upload_temp(serial, content)
    root_shell = shlex.quote(elevation) if elevation else "sh"
    return shell(
        serial,
        f"{_remove_on_exit(tmp)}; {root_shell} < {shlex.quote(tmp)}",
        check=check,
    )


def start(serial: Optional[str], args: Iterable[str]) -> subprocess.Popen:
    """Starts `adb <args>` in the background."""
    cmd = [*_adb(serial), *args]
    logger.debug(f"Starting: {' '.join(cmd)}")
    return subprocess.Popen(cmd, stdin=subprocess.DEVNULL)


def _adb(serial: Optional[str]) -> list:
    return ["adb", "-s", serial] if serial else ["adb"]


def _upload_temp(serial: Optional[str], content: str) -> str:
    """Copies `content` to a new device temp file and returns its path."""
    cmd = f"mktemp -p {DEVICE_TMP_DIR}"
    tmp = shell(serial, cmd).stdout.decode("utf-8").strip()
    with tempfile.NamedTemporaryFile(
        mode="w", delete=True, delete_on_close=False
    ) as local:
        local.write(content)
        # Ensure data is written to disk before adb reads it
        local.flush()
        run(serial, ["push", local.name, tmp])
    return tmp


def _remove_on_exit(path: str) -> str:
    return f"trap {shlex.quote(f'rm -f {shlex.quote(path)}')} EXIT"
