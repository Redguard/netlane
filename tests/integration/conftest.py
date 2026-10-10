import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Generator, Optional

import pytest

from netlane.config import Config, load_config
from netlane.modes import wireguard_ssh_reverse

TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent.parent
KEY_PATH = TESTS_DIR / "keys" / "id_ed25519"


def is_port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    """Checks if a TCP port is open."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def _get_default_gateway() -> Optional[str]:
    """Extracts the default IPv4 gateway address from /proc/net/route if inside a Linux container."""
    try:
        route_file = Path("/proc/net/route")
        if route_file.exists():
            for line in route_file.read_text().splitlines():
                fields = line.strip().split()
                if len(fields) >= 3 and fields[1] == "00000000":
                    val = int(fields[2], 16)
                    return socket.inet_ntoa(val.to_bytes(4, byteorder="little"))
    except Exception:
        pass
    return None


def _detect_vps_host(port: int) -> str:
    if "NETLANE_TEST_VPS_HOST" in os.environ:
        return os.environ["NETLANE_TEST_VPS_HOST"]
    if is_port_open("127.0.0.1", port, timeout=0.5):
        return "127.0.0.1"
    if is_port_open("host.docker.internal", port, timeout=0.5):
        return "host.docker.internal"
    gateway = _get_default_gateway()
    if gateway and is_port_open(gateway, port, timeout=0.5):
        return gateway
    return "127.0.0.1"


VPS_PORT = int(os.environ.get("NETLANE_TEST_VPS_PORT", "2222"))
VPS_HOST = _detect_vps_host(VPS_PORT)
VPS_USER = os.environ.get("NETLANE_TEST_VPS_USER", "ubuntu")


@pytest.fixture(scope="session", autouse=True)
def configure_ssh():
    """Configures ~/.ssh/config so ssh/scp transparently use test keys and ports."""
    ssh_dir = Path.home() / ".ssh"
    ssh_dir.mkdir(parents=True, exist_ok=True)
    config_file = ssh_dir / "config"

    # Ensure correct permissions on the test private key
    if KEY_PATH.exists():
        KEY_PATH.chmod(0o600)

    marker = "# --- NETLANE TEST CONFIG ---"
    block = f"""{marker}
Host {VPS_HOST} netlane-vps
    Port {VPS_PORT}
    User {VPS_USER}
    IdentityFile {KEY_PATH}
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    LogLevel ERROR
{marker}
"""

    existing_content = config_file.read_text() if config_file.exists() else ""
    if marker in existing_content:
        # Replace existing test block
        before, _, remainder = existing_content.partition(marker)
        _, _, after = remainder.partition(marker)
        new_content = before.rstrip() + "\n" + block + after.lstrip()
    else:
        new_content = existing_content + ("\n" if existing_content else "") + block

    config_file.write_text(new_content)
    config_file.chmod(0o600)

    yield

    # Clean up marker on teardown if desired
    if config_file.exists():
        content = config_file.read_text()
        if marker in content:
            before, _, remainder = content.partition(marker)
            _, _, after = remainder.partition(marker)
            cleaned = before.rstrip() + "\n" + after.lstrip()
            config_file.write_text(cleaned.strip() + "\n")


@pytest.fixture(scope="session")
def vps_server(configure_ssh):
    """
    Ensures the VPS container or server is reachable.
    Skips integration tests if the VPS is not available.
    """
    if not is_port_open(VPS_HOST, VPS_PORT, timeout=2.0):
        pytest.skip(
            f"VPS server at {VPS_HOST}:{VPS_PORT} is not reachable. "
            "Start the test environment with: docker compose -f docker-compose.test.yml up -d"
        )

    # Verify SSH connection works
    ssh_cmd = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=3",
        f"{VPS_USER}@{VPS_HOST}",
        "echo OK",
    ]
    res = subprocess.run(ssh_cmd, capture_output=True, text=True)
    if res.returncode != 0:
        pytest.skip(
            f"SSH connection to {VPS_USER}@{VPS_HOST}:{VPS_PORT} failed: {res.stderr.strip()}"
        )

    return {"host": VPS_HOST, "port": VPS_PORT, "user": VPS_USER}


@pytest.fixture
def vps_exec(vps_server):
    """Helper to run commands inside the VPS via SSH for test assertions."""

    def _exec(
        cmd: str, elevation: str = "sudo", check: bool = True
    ) -> subprocess.CompletedProcess:
        ssh_cmd = [
            "ssh",
            f"{VPS_USER}@{VPS_HOST}",
            f"{elevation} {cmd}" if elevation else cmd,
        ]
        return subprocess.run(ssh_cmd, capture_output=True, text=True, check=check)

    return _exec


class NetlaneRunner:
    def __init__(self, config_path: Path):
        self.config_path = config_path
        self.config: Config = load_config(config_path)

    def _run_cmd(
        self,
        cmd: list[str],
        input_data: Optional[str] = None,
        check: bool = False,
    ) -> subprocess.CompletedProcess:
        res = subprocess.run(
            cmd,
            input=input_data,
            capture_output=True,
            text=True,
            check=check,
        )
        if res.stdout:
            sys.stdout.write(res.stdout)
            sys.stdout.flush()
        if res.stderr:
            sys.stderr.write(res.stderr)
            sys.stderr.flush()
        return res

    def run(
        self,
        *args: str,
        stdin: Optional[str] = None,
        check: bool = False,
    ) -> subprocess.CompletedProcess:
        """Runs the `netlane` CLI with the configured config path and given arguments."""
        cmd = [
            "uv",
            "run",
            "netlane",
            "--config",
            str(self.config_path),
            *args,
        ]
        return self._run_cmd(cmd, input_data=stdin, check=check)

    def setup(
        self, profile: str, distro: str = "ubuntu", check: bool = True
    ) -> subprocess.CompletedProcess:
        """Runs `netlane setup`, automatically providing the confirmation string to stdin."""
        profile_obj = self.config.profiles.get(profile)
        if profile_obj is None:
            raise ValueError(f"Profile {profile} not found in config")

        ssh_target = (
            f"{profile_obj.mode_opts.ssh_user}@{profile_obj.mode_opts.ssh_host}"
        )
        cmd = [
            "uv",
            "run",
            "netlane",
            "--config",
            str(self.config_path),
            "-v",
            "setup",
            profile,
            "--distro",
            distro,
        ]

        # Feed target into stdin to answer the confirmation prompt
        return self._run_cmd(cmd, input_data=f"{ssh_target}\n", check=check)

    def pair(
        self,
        profile: str,
        save_path: Optional[Path] = None,
        force: bool = True,
        check: bool = True,
    ) -> subprocess.CompletedProcess:
        """Runs `netlane pair`."""
        cmd = [
            "uv",
            "run",
            "netlane",
            "--config",
            str(self.config_path),
            "-v",
            "pair",
            profile,
        ]
        if force:
            cmd.append("--force")
        if save_path:
            cmd.extend(["--save", str(save_path)])

        return self._run_cmd(cmd, check=check)

    @contextmanager
    def up(
        self, profile: str, ready_timeout: float = 15.0
    ) -> Generator[subprocess.Popen, None, None]:
        """Runs `netlane up` as a background process until context exit."""
        cmd = [
            "uv",
            "run",
            "netlane",
            "--config",
            str(self.config_path),
            "-v",
            "up",
            profile,
        ]
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            preexec_fn=os.setsid,
        )
        try:
            start_time = time.time()
            output_lines = []
            ready = False
            while time.time() - start_time < ready_timeout:
                if proc.poll() is not None:
                    break
                if proc.stdout is not None:
                    line = proc.stdout.readline()
                    if line:
                        output_lines.append(line)
                        sys.stdout.write(line)
                        sys.stdout.flush()
                        if "Local tunnel endpoints:" in line:
                            ready = True
                            break
            if not ready:
                if proc.poll() is None:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                remaining = proc.communicate(timeout=2)[0] if proc.stdout else ""
                if remaining:
                    sys.stdout.write(remaining)
                    sys.stdout.flush()
                full_output = "".join(output_lines) + (remaining or "")
                raise RuntimeError(
                    f"netlane up failed to become ready within {ready_timeout}s:\n{full_output}"
                )
            yield proc
        finally:
            if proc.poll() is None:
                os.killpg(os.getpgid(proc.pid), signal.SIGINT)
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
            # Safety teardown
            self._run_cmd(
                [
                    "uv",
                    "run",
                    "netlane",
                    "--config",
                    str(self.config_path),
                    "-v",
                    "down",
                    profile,
                ]
            )

    def down(self, profile: str, check: bool = True) -> subprocess.CompletedProcess:
        """Runs `netlane down`."""
        cmd = [
            "uv",
            "run",
            "netlane",
            "--config",
            str(self.config_path),
            "-v",
            "down",
            profile,
        ]
        return self._run_cmd(cmd, check=check)


@pytest.fixture(scope="session")
def setup_vps(vps_server, tmp_path_factory):
    """Provisions the VPS once per test session."""
    cfg = tmp_path_factory.mktemp("cfg") / "config.toml"
    cfg.write_text(f"""[profiles.jailed]
mode = "wireguard_ssh_reverse"

[profiles.jailed.mode_opts]
ssh_host = "{vps_server['host']}"
ssh_user = "{vps_server['user']}"
elevation = "sudo"
tunnels = {{ proxy_main = 8080 }}
""")
    res = subprocess.run(
        [
            "uv",
            "run",
            "netlane",
            "--config",
            str(cfg),
            "-v",
            "setup",
            "jailed",
            "--distro",
            "ubuntu",
        ],
        input=f"{vps_server['user']}@{vps_server['host']}\n",
        capture_output=True,
        text=True,
    )
    if res.stdout:
        sys.stdout.write(res.stdout)
        sys.stdout.flush()
    if res.stderr:
        sys.stderr.write(res.stderr)
        sys.stderr.flush()
    assert res.returncode == 0
    return res


@pytest.fixture
def integration_config(tmp_path, setup_vps) -> Path:
    """Generates a temporary config.toml pointing to the test VPS."""
    config_content = f"""[profiles.jailed]
mode = "wireguard_ssh_reverse"

rules = [
  {{ name = "Reject IPv6", saddr = ["::/0"], target = "action:reject" }},
  {{ name = "Redirect HTTP", protocol = ["tcp"], dport = [80], target = "tunnel:proxy_main" }},
  {{ name = "Default Route", target = "action:passthrough" }},
]

[profiles.jailed.mode_opts]
ssh_host = "{VPS_HOST}"
ssh_user = "{VPS_USER}"
elevation = "sudo"
tunnels = {{ proxy_main = 8080 }}

[profiles.jailed.hooks]
pre_up = ""
post_down = ""
"""
    config_file = tmp_path / "config.toml"
    config_file.write_text(config_content)
    return config_file


@pytest.fixture
def netlane(integration_config) -> NetlaneRunner:
    """Provides a NetlaneRunner instance configured with the test config."""
    return NetlaneRunner(integration_config)


@pytest.fixture
def paired_vps(netlane: NetlaneRunner) -> NetlaneRunner:
    """Ensures the profile is paired on the VPS."""
    netlane.pair("jailed", force=True)
    return netlane


@pytest.fixture
def create_netlane():
    """Factory fixture to create NetlaneRunner instances for custom configs."""

    def _create(config_path: Path) -> NetlaneRunner:
        return NetlaneRunner(config_path)

    return _create
