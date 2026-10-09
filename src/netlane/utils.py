import json
import os
import subprocess
import sys
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from netlane import APP_NAME

logger = logging.getLogger(__name__)

# Seconds within which a second Ctrl-C aborts the teardown.
ABORT_WINDOW = 2


COLOR_CHOICES = ["auto", "always", "never"]

RESET = "\033[0m"
DIM = "\033[2m"
LEVEL_COLORS = {
    logging.DEBUG: "\033[34m",
    logging.INFO: "\033[32m",
    logging.WARNING: "\033[33m",
    logging.ERROR: "\033[31m",
    logging.CRITICAL: "\033[1;31m",
}


class ColorFormatter(logging.Formatter):
    """Colors the level name by severity and dims DEBUG lines as a whole."""

    def format(self, record: logging.LogRecord) -> str:
        line_style = DIM if record.levelno == logging.DEBUG else ""
        # A copy, as other handlers format the same record.
        record = logging.makeLogRecord(record.__dict__)
        color = LEVEL_COLORS.get(record.levelno, "")
        record.levelname = f"{color}{record.levelname}{RESET}{line_style}"
        return f"{line_style}{super().format(record)}{RESET}"


def use_color(stream, color: str) -> bool:
    """auto colors terminals unless NO_COLOR is set (https://no-color.org)."""
    if color != "auto":
        return color == "always"
    return (
        stream.isatty()
        and not os.environ.get("NO_COLOR")
        and os.environ.get("TERM") != "dumb"
    )


class JsonFormatter(logging.Formatter):
    """One JSON object per line, extended by `context` such as the profile and step."""

    def __init__(self, context: dict[str, str]):
        super().__init__()
        self.context = context

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "time": datetime.fromtimestamp(record.created)
            .astimezone()
            .isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            **self.context,
            "message": record.getMessage(),
        }
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry)


def setup_logging(
    verbose: bool, color: str, log_file: Optional[Path], context: dict[str, str]
):
    """The console shows DEBUG only if `verbose`, `log_file` always gets everything."""
    formatter = ColorFormatter if use_color(sys.stdout, color) else logging.Formatter
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.DEBUG if verbose else logging.INFO)
    console.setFormatter(
        formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
    )
    handlers: list[logging.Handler] = [console]

    if log_file is not None:
        file = logging.FileHandler(log_file, encoding="utf-8")
        file.setFormatter(JsonFormatter(context))
        handlers.append(file)

    logging.basicConfig(level=logging.DEBUG, handlers=handlers)


def config_dir() -> Path:
    """Follows https://dirs.dev with the project path `APP_NAME`."""
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming"
        return Path(appdata) / APP_NAME / "config"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / APP_NAME
    # The XDG spec ignores relative paths.
    xdg_config_home = os.environ.get("XDG_CONFIG_HOME", "")
    if not os.path.isabs(xdg_config_home):
        xdg_config_home = Path.home() / ".config"
    return Path(xdg_config_home) / APP_NAME


def write_private_file(path: Path, content: str):
    """Writes `content` to `path`, creating it readable by the current user only."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(content)


def teardown_sigint_handler():
    """Returns a SIGINT handler that only interrupts when pressed twice within ABORT_WINDOW seconds."""
    last_press = None

    def handler(signum, frame):
        nonlocal last_press
        now = time.monotonic()
        if last_press is not None and now - last_press <= ABORT_WINDOW:
            raise KeyboardInterrupt
        last_press = now
        logger.warning(
            f"Teardown in progress. Press Ctrl-C again within {ABORT_WINDOW}s to abort it."
        )

    return handler


def run_cmd(
    cmd, input_bytes=None, capture_output=True, check=True, secret=False, cwd=None
):
    """With `secret`, stdout isn't logged, e.g. for commands printing keys."""
    logger.debug(f"Executing: {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd,
            input=input_bytes,
            capture_output=capture_output,
            check=check,
            cwd=cwd,
        )
        if capture_output:
            if result.stdout and not secret:
                logger.debug(f"stdout:\n{result.stdout.decode('utf-8').strip()}")
            if result.stderr:
                logger.debug(f"stderr:\n{result.stderr.decode('utf-8').strip()}")
        return result
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed with exit code {e.returncode}: {' '.join(cmd)}")
        if capture_output and e.stderr:
            logger.error(f"Error output:\n{e.stderr.decode('utf-8').strip()}")
        raise
