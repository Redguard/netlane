import logging
import shlex
import subprocess
import tempfile
from pathlib import Path
from typing import Iterable, Optional

from netlane.utils import run_cmd

logger = logging.getLogger(__name__)


def run(
    target: str,
    cmd: str,
    elevation: Optional[str] = None,
    tty: bool = False,
    check: bool = True,
) -> subprocess.CompletedProcess:
    """Runs `cmd` in a shell on `target`, elevated with `elevation` if given. With `tty`, output is shown live and prompts such as sudo's password work."""
    if elevation is not None:
        cmd = _elevate(elevation, cmd)
    args = ["ssh", "-t", target] if tty else ["ssh", target]
    return run_cmd([*args, cmd], capture_output=not tty, check=check)


def run_script(
    target: str,
    elevation: str,
    content: str,
    runner: Iterable[str],
    args: Iterable[str] = (),
) -> None:
    """Runs `content` elevated as `<runner> <script> <args>` from a remote temp file."""
    tmp = _upload_temp(target, content)
    cmd = shlex.join([*runner, tmp, *args])
    run(target, f"{_remove_on_exit(tmp)}; {_elevate(elevation, cmd)}", tty=True)


def install_file(target: str, elevation: str, content: str, dest_path: str) -> None:
    """Places `content` at `dest_path`, owned by root and readable by root only."""
    tmp = _upload_temp(target, content)
    cmd = shlex.join(
        ["install", "-m", "600", "-o", "root", "-g", "root", tmp, dest_path]
    )
    run(target, f"{_remove_on_exit(tmp)}; {_elevate(elevation, cmd)}", tty=True)


def start(target: str, options: Iterable[str]) -> subprocess.Popen:
    """Starts ssh to `target` with `options` in the background."""
    cmd = ["ssh", *options, target]
    logger.debug(f"Starting: {' '.join(cmd)}")
    return subprocess.Popen(cmd)


def _elevate(elevation: str, cmd: str) -> str:
    """Wraps `cmd` to run as root. su takes the command itself, sudo and doas run a program."""
    if not elevation:
        return cmd
    if elevation == "su":
        return f"su -c {shlex.quote(cmd)}"
    return f"{shlex.quote(elevation)} sh -c {shlex.quote(cmd)}"


def _upload_temp(target: str, content: str) -> str:
    """Copies `content` to a new remote temp file and returns its path."""
    tmp = run(target, "mktemp").stdout.decode("utf-8").strip()
    # scp splits host and path at ":", so an IPv6 host needs brackets.
    user, at, host = target.rpartition("@")
    if ":" in host:
        host = f"[{host}]"
    with tempfile.NamedTemporaryFile(
        mode="w", delete=True, delete_on_close=False
    ) as local:
        local.write(content)
        # Ensure data is written to disk before scp reads it
        local.flush()
        # A bare file name, as some scp builds read a drive letter like C: as a host.
        path = Path(local.name)
        run_cmd(["scp", path.name, f"{user}{at}{host}:{tmp}"], cwd=path.parent)
    return tmp


def _remove_on_exit(path: str) -> str:
    return f"trap {shlex.quote(f'rm -f {shlex.quote(path)}')} EXIT"
