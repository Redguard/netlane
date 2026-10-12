import os
import queue
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Generator, Optional

import pytest

from netlane.config import Config, load_config
from netlane.modes import wireguard_ssh_reverse

TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent.parent


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


def _detect_host(env_var: str, port: int) -> str:
    """Finds the address a test container's published `port` is reachable on."""
    if env_var in os.environ:
        return os.environ[env_var]
    if is_port_open("127.0.0.1", port, timeout=0.5):
        return "127.0.0.1"
    if is_port_open("host.docker.internal", port, timeout=0.5):
        return "host.docker.internal"
    gateway = _get_default_gateway()
    if gateway and is_port_open(gateway, port, timeout=0.5):
        return gateway
    return "127.0.0.1"


VPS_PORT = int(os.environ.get("NETLANE_TEST_VPS_PORT", "2222"))
VPS_HOST = _detect_host("NETLANE_TEST_VPS_HOST", VPS_PORT)
VPS_USER = os.environ.get("NETLANE_TEST_VPS_USER", "ubuntu")
VPS_CONTAINER = os.environ.get("NETLANE_TEST_VPS_CONTAINER", "netlane-vps")

ADB_PORT = int(os.environ.get("NETLANE_TEST_ADB_PORT", "5555"))
ADB_HOST = _detect_host("NETLANE_TEST_ADB_HOST", ADB_PORT)
ADB_SERIAL = f"{ADB_HOST}:{ADB_PORT}"
# Redroid's adbd runs as the shell user and ships su. Set to "" for a device with root adbd.
ADB_ELEVATION = os.environ.get("NETLANE_TEST_ADB_ELEVATION", "su")

# The WireGuard client of the `wg_client` fixture, a container beyond the gateway.
CLIENT_CONTAINER = os.environ.get("NETLANE_TEST_CLIENT_CONTAINER", "netlane-client")
CLIENT_WG_IFACE = "wgclient"
# Routing table holding the client's default routes into the tunnel.
CLIENT_ROUTE_TABLE = 51820

REMOTE_CONTAINER = os.environ.get("NETLANE_TEST_REMOTE_CONTAINER", "netlane-remote")

# Stands in for the placeholder app of the shipped rooted profile. It runs as the
# ADB shell's uid, so traffic sent from an unelevated shell is that app's traffic.
ROOTED_APP = "com.android.shell"

# Set to "1" (as CI does) to fail instead of skip when a test container is unavailable.
REQUIRE_SERVICES = os.environ.get("NETLANE_TEST_REQUIRE_SERVICES") == "1"


def _unavailable(reason: str) -> None:
    """Skips the test, or fails it when the test containers are required."""
    if REQUIRE_SERVICES:
        pytest.fail(reason)
    pytest.skip(reason)


def _authorize_test_key(public_key: str) -> Optional[str]:
    """Installs the session's public key in the VPS container. Returns an error message on failure."""
    if shutil.which("docker") is None:
        return "Docker ('docker') not found locally."
    res = subprocess.run(
        [
            "docker",
            "exec",
            "-i",
            "-u",
            VPS_USER,
            VPS_CONTAINER,
            "sh",
            "-c",
            "umask 077 && mkdir -p ~/.ssh && cat > ~/.ssh/authorized_keys",
        ],
        input=public_key,
        capture_output=True,
        text=True,
    )
    return res.stderr.strip() if res.returncode != 0 else None


@pytest.fixture(scope="session", autouse=True)
def configure_ssh(tmp_path_factory):
    """
    Configures ~/.ssh/config so ssh/scp transparently use test keys and ports.
    Yields the public half of a key pair generated for this test session.
    """
    ssh_dir = Path.home() / ".ssh"
    ssh_dir.mkdir(parents=True, exist_ok=True)
    config_file = ssh_dir / "config"

    key_path = tmp_path_factory.mktemp("keys") / "id_ed25519"
    subprocess.run(
        [
            "ssh-keygen",
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "netlane-test",
            "-f",
            str(key_path),
        ],
        check=True,
    )

    marker = "# --- NETLANE TEST CONFIG ---"
    block = f"""{marker}
Host {VPS_HOST} netlane-vps
    Port {VPS_PORT}
    User {VPS_USER}
    IdentityFile {key_path}
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

    yield key_path.with_suffix(".pub").read_text()

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
        _unavailable(
            f"VPS server at {VPS_HOST}:{VPS_PORT} is not reachable. "
            "Start the test environment with: docker compose -f docker-compose.test.yml up -d"
        )

    authorize_error = _authorize_test_key(configure_ssh)

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
        reason = f"SSH connection to {VPS_USER}@{VPS_HOST}:{VPS_PORT} failed: {res.stderr.strip()}"
        if authorize_error:
            reason += f" (could not install the test key in container '{VPS_CONTAINER}': {authorize_error})"
        _unavailable(reason)

    return {"host": VPS_HOST, "port": VPS_PORT, "user": VPS_USER}


@pytest.fixture(scope="session")
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
        self,
        profile: str,
        ready_timeout: float = 15.0,
        exit_timeout: float = 20.0,
        check: bool = True,
    ) -> Generator[subprocess.Popen, None, None]:
        """
        Runs `netlane up` as a background process and interrupts it on context exit.

        Leaving the context sends Ctrl-C and requires `up` to tear down on its own
        and exit cleanly. `netlane down` only runs as a fallback when something
        failed, so that a broken teardown is not hidden and later tests start clean.
        Without `check`, `up` may exit with any code, e.g. when a test ended it.
        """
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
            start_new_session=True,
        )
        assert proc.stdout is not None
        stdout = proc.stdout
        # None marks EOF. The reader keeps draining until the process exits, so a
        # verbose `up` can never block on a full pipe.
        lines: queue.Queue[Optional[str]] = queue.Queue()

        def _drain() -> None:
            for line in stdout:
                lines.put(line)
            lines.put(None)

        reader = threading.Thread(target=_drain, daemon=True)
        reader.start()

        output: list[str] = []
        eof = False

        def _collect(deadline: float, until: Optional[str] = None) -> bool:
            """Echoes output until `until` shows up, EOF or the deadline. True if `until` was seen."""
            nonlocal eof
            while not eof:
                try:
                    line = lines.get(timeout=max(deadline - time.monotonic(), 0))
                except queue.Empty:
                    return False
                if line is None:
                    eof = True
                    break
                output.append(line)
                sys.stdout.write(line)
                sys.stdout.flush()
                if until is not None and until in line:
                    return True
            return False

        def _kill() -> None:
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
            _collect(time.monotonic() + 2)

        def _interrupt() -> Optional[int]:
            """Sends Ctrl-C to `up` and returns its exit code, or None if it did not exit in time."""
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGINT)
            # Do not rely on EOF alone, a leftover child may keep the pipe open.
            deadline = time.monotonic() + exit_timeout
            while proc.poll() is None and time.monotonic() < deadline:
                _collect(min(deadline, time.monotonic() + 0.2))
            if proc.poll() is None:
                _kill()
                return None
            _collect(time.monotonic() + 2)
            return proc.returncode

        try:
            if not _collect(
                time.monotonic() + ready_timeout, "Local tunnel endpoints:"
            ):
                exited = proc.poll() is not None or eof
                _kill()
                reason = (
                    f"exited with code {proc.returncode} before becoming ready"
                    if exited
                    else f"failed to become ready within {ready_timeout}s"
                )
                raise RuntimeError(f"netlane up {reason}:\n{''.join(output)}")
            yield proc
        except BaseException:
            _interrupt()
            self.down(profile, check=False)
            raise

        returncode = _interrupt()
        if returncode != 0:
            self.down(profile, check=False)
            if returncode is not None and not check:
                return
            reason = (
                f"did not exit within {exit_timeout}s"
                if returncode is None
                else f"exited with code {returncode}"
            )
            raise RuntimeError(f"netlane up {reason} after Ctrl-C:\n{''.join(output)}")

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


@pytest.fixture(scope="session")
def create_netlane():
    """Factory fixture to create NetlaneRunner instances for custom configs."""

    def _create(config_path: Path) -> NetlaneRunner:
        return NetlaneRunner(config_path)

    return _create


def _adb(*args: str, timeout: float = 30.0) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["adb", "-s", ADB_SERIAL, *args],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


@pytest.fixture(scope="session")
def adb_device():
    """
    Connects ADB to the Android container and waits until it has booted.
    Skips integration tests if the device is not available.
    """
    start_hint = (
        "Start the test environment with: "
        "docker compose -f docker-compose.test.yml up -d"
    )
    if shutil.which("adb") is None:
        _unavailable("ADB ('adb') not found locally.")
    if not is_port_open(ADB_HOST, ADB_PORT, timeout=2.0):
        _unavailable(f"Android device at {ADB_SERIAL} is not reachable. {start_hint}")

    subprocess.run(["adb", "connect", ADB_SERIAL], capture_output=True, text=True)
    # The package manager only answers once the system has booted.
    deadline = time.time() + 90
    booted = False
    while time.time() < deadline:
        res = _adb("shell", "-n", "getprop sys.boot_completed", timeout=10)
        if res.returncode == 0 and res.stdout.strip() == "1":
            booted = True
            break
        time.sleep(2)
    if not booted:
        _unavailable(f"Android device at {ADB_SERIAL} did not finish booting.")

    return {"serial": ADB_SERIAL, "elevation": ADB_ELEVATION}


def _device_exec(
    cmd: str, check: bool = True, timeout: float = 30.0, root: bool = True
) -> subprocess.CompletedProcess:
    if root and ADB_ELEVATION:
        # Not every su takes -c, but they all read a script from stdin.
        cmd = f"echo {shlex.quote(cmd)} | {ADB_ELEVATION}"
    res = _adb("shell", "-n", cmd, timeout=timeout)
    if check:
        res.check_returncode()
    return res


@pytest.fixture(scope="session")
def device_exec(adb_device):
    """Helper to run commands as root on the Android device for test assertions."""
    return _device_exec


@pytest.fixture
def adb_reverse_list(adb_device):
    """Helper returning the device's active `adb reverse` tunnels."""

    def _list() -> str:
        res = _adb("reverse", "--list")
        res.check_returncode()
        return res.stdout

    return _list


def _adb_reverse_config(rules: str = "", tunnels: str = "proxy_main = 8080") -> str:
    """Builds a config.toml with a 'rooted' adb_reverse profile for the test device."""
    return f"""[profiles.rooted]
mode = "adb_reverse"

rules = [
{rules}
]

[profiles.rooted.mode_opts]
serial = "{ADB_SERIAL}"
elevation = "{ADB_ELEVATION}"
tunnels = {{ {tunnels} }}
"""


@pytest.fixture
def adb_reverse_config(adb_device):
    """Factory fixture building 'rooted' adb_reverse configs with custom rules or tunnels."""
    return _adb_reverse_config


@pytest.fixture
def adb_integration_config(tmp_path, adb_device) -> Path:
    """Generates a temporary config.toml pointing to the test Android device."""
    config_file = tmp_path / "config.toml"
    # The tunnel rule is restricted to IPv4, the container kernel may lack IPv6 NAT.
    config_file.write_text(_adb_reverse_config("""
  { name = "Redirect HTTP", daddr = ["0.0.0.0/0"], protocol = ["tcp"], dport = [80], target = "tunnel:proxy_main" },
  { name = "Default Route", target = "action:passthrough" },
"""))
    return config_file


@pytest.fixture
def netlane_adb(adb_integration_config) -> Generator[NetlaneRunner, None, None]:
    """Provides a NetlaneRunner for the 'rooted' profile and leaves the device clean."""
    runner = NetlaneRunner(adb_integration_config)
    runner.down("rooted", check=False)
    yield runner
    runner.down("rooted", check=False)


@dataclass
class Sent:
    """A line a test sent from the client or device, with a payload unique to it."""

    payload: str
    returncode: int
    reply: str

    @property
    def line(self) -> bytes:
        """The line as a `local_listener` receives it."""
        return f"{self.payload}\n".encode()


@pytest.fixture(scope="session")
def local_listener():
    """
    Factory for a listener on a local tunnel port, standing in for the analyst's proxy.
    Yields the list of lines it received, each of which it answers with `reply`.
    """

    @contextmanager
    def _listen(
        port: int = 8080, host: str = "127.0.0.1", reply: bytes = b"pong\n"
    ) -> Generator[list[bytes], None, None]:
        received: list[bytes] = []
        stop = threading.Event()

        def serve(listener: socket.socket) -> None:
            while not stop.is_set():
                try:
                    conn, _ = listener.accept()
                except TimeoutError:
                    continue
                except OSError:
                    return
                with conn:
                    conn.settimeout(5)
                    try:
                        received.append(conn.recv(1024))
                        conn.sendall(reply)
                    except OSError:
                        pass

        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        with socket.create_server((host, port), family=family) as listener:
            # A short timeout lets the thread notice `stop`.
            listener.settimeout(0.2)
            server = threading.Thread(target=serve, args=(listener,), daemon=True)
            server.start()
            try:
                yield received
            finally:
                stop.set()
                server.join(timeout=10)

    return _listen


class Remote:
    """A host beyond the gateway or device, which records the lines that reach it."""

    def __init__(self, address: str):
        self.address = address

    def peers(self, endpoint: str, payload: str, wait: float = 0.0) -> list[str]:
        """
        Source addresses `payload` arrived from on `endpoint` (e.g. "tcp/443"), waiting
        up to `wait` seconds for it. Empty if it did not arrive.
        """
        deadline = time.monotonic() + wait
        while True:
            res = subprocess.run(
                ["docker", "exec", REMOTE_CONTAINER, "cat", "/received"],
                capture_output=True,
                text=True,
                check=True,
            )
            records = [line.split(" ", 2) for line in res.stdout.splitlines()]
            peers = [r[1] for r in records if [r[0], r[2]] == [endpoint, payload]]
            if peers or time.monotonic() >= deadline:
                return peers
            time.sleep(0.2)


def _container_address(container: str, role: str) -> str:
    """Address of a test container on the test network. Skips the test if it is not running."""
    if shutil.which("docker") is None:
        _unavailable("Docker ('docker') not found locally.")
    res = subprocess.run(
        [
            "docker",
            "inspect",
            "-f",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            container,
        ],
        capture_output=True,
        text=True,
    )
    address = res.stdout.strip()
    if res.returncode != 0 or not address:
        _unavailable(
            f"{role} container '{container}' is not running. "
            "Start the test environment with: "
            "docker compose -f docker-compose.test.yml up -d"
        )
    return address


@pytest.fixture(scope="session")
def remote() -> Remote:
    """The remote container. Skips integration tests if it is not available."""
    return Remote(_container_address(REMOTE_CONTAINER, "Remote"))


@pytest.fixture(scope="session")
def shipped_config(tmp_path_factory) -> Path:
    """The repository's example config.toml, with its profiles pointed at the test containers."""
    content = (REPO_ROOT / "config.toml").read_text()
    for pattern, replacement in (
        (r'^ssh_host = ".*"$', f'ssh_host = "{VPS_HOST}"'),
        (r'^ssh_user = ".*"$', f'ssh_user = "{VPS_USER}"'),
        (r'^# serial = ".*"$', f'serial = "{ADB_SERIAL}"'),
        (r'^elevation = "su"$', f'elevation = "{ADB_ELEVATION}"'),
        (r'"com\.example\.app"', f'"{ROOTED_APP}"'),
    ):
        content, count = re.subn(pattern, replacement, content, flags=re.MULTILINE)
        assert count == 1, f"config.toml no longer has exactly one {pattern!r}"
    config_file = tmp_path_factory.mktemp("shipped") / "config.toml"
    config_file.write_text(content)
    return config_file


@pytest.fixture(scope="session")
def device_send(adb_device) -> Callable[..., Sent]:
    """
    Helper sending a line from the Android device. It is sent by the ADB shell's
    uid, or by root with `root=True`.
    """

    def _send(
        host: str, port: int, udp: bool = False, root: bool = False, timeout: int = 5
    ) -> Sent:
        payload = uuid.uuid4().hex
        flags = ("-6 " if ":" in host else "") + ("-u " if udp else "")
        # nc exits on stdin EOF, keep it open until the reply made it back.
        cmd = (
            f"(echo {payload}; sleep 1) | "
            f"timeout {timeout} nc {flags}-w {timeout} {host} {port}"
        )
        res = _device_exec(cmd, check=False, root=root)
        return Sent(payload, res.returncode, res.stdout)

    return _send


class WireguardClient:
    """A WireGuard client of the gateway, routing all of its traffic through the tunnel."""

    def __init__(self, vps_exec):
        self._vps_exec = vps_exec

    def wait_for_handshake(self, timeout: float = 30.0) -> None:
        """Blocks until the client completed a handshake with the gateway."""
        iface = wireguard_ssh_reverse.WG_IFACE
        # The client retries its handshake every 5 seconds until the gateway is up.
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            res = self._vps_exec(f"wg show {iface} latest-handshakes", check=False)
            fields = res.stdout.split()
            if len(fields) == 2 and fields[1] != "0":
                return
            time.sleep(0.5)
        raise RuntimeError(
            f"No WireGuard handshake from the client within {timeout}s:\n"
            + self._vps_exec(f"wg show {iface}", check=False).stdout
        )

    def send(self, host: str, port: int, udp: bool = False, timeout: int = 5) -> Sent:
        """
        Sends a line from the client. Over TCP, `reply` is the first line of the
        answer and `returncode` is 124 if the connection timed out.
        """
        self.wait_for_handshake()
        payload = uuid.uuid4().hex
        # bash connects on its own, so the client needs no nc.
        if udp:
            script = f"echo {payload} > /dev/udp/{host}/{port}"
        else:
            script = (
                f"exec 3<>/dev/tcp/{host}/{port} && echo {payload} >&3 "
                "&& head -n 1 <&3"
            )
        res = _client_exec(f"timeout {timeout} bash -c {shlex.quote(script)}")
        return Sent(payload, res.returncode, res.stdout)


def _client_exec(script: str, check: bool = False) -> subprocess.CompletedProcess:
    """Runs a script in the WireGuard client container."""
    return subprocess.run(
        ["docker", "exec", CLIENT_CONTAINER, "bash", "-c", script],
        capture_output=True,
        text=True,
        check=check,
    )


def _remove_wg_client() -> None:
    # Deleting the interface also removes the routes into it.
    _client_exec(f"ip link del {CLIENT_WG_IFACE}")
    for family in ("-4", "-6"):
        _client_exec(f"ip {family} rule del table {CLIENT_ROUTE_TABLE}")


@pytest.fixture(scope="session")
def wg_client(vps_exec):
    """
    Factory for a WireGuard client connected with a client config from `netlane pair`.

    The client is a container of its own, standing in for the mobile device. It
    reaches the gateway's WireGuard port over the network and routes everything
    else through the tunnel, as the WireGuard app does with `AllowedIPs` of all.
    """
    _container_address(CLIENT_CONTAINER, "WireGuard client")
    # The client config has the address the tests reach the VPS on, which is a
    # published port. The client is on the VPS's network and uses it directly.
    gateway = _container_address(VPS_CONTAINER, "VPS")

    @contextmanager
    def _connect(client_conf: str) -> Generator[WireguardClient, None, None]:
        addresses: list[str] = []
        setconf: list[str] = []
        for line in client_conf.splitlines():
            key, _, value = (part.strip() for part in line.partition("="))
            if key == "Address":
                addresses = [address.strip() for address in value.split(",")]
            elif key == "Endpoint":
                setconf.append(f"Endpoint = {gateway}:{value.rpartition(':')[2]}")
            elif key != "DNS":
                # Address and DNS are wg-quick's, `wg setconf` rejects them.
                setconf.append(line)

        iface, table = CLIENT_WG_IFACE, CLIENT_ROUTE_TABLE
        script = [
            "set -e",
            f"ip link add {iface} type wireguard",
            f"wg setconf {iface} /dev/stdin <<'EOF'",
            *setconf,
            "EOF",
            # nodad: an IPv6 address is not usable while its duplicate detection runs.
            *(f"ip addr add {a} dev {iface} nodad" for a in addresses),
            f"ip link set {iface} up",
            # All traffic enters the tunnel, except the tunnel's own packets to the
            # gateway. This includes the test network, which the client is on as well.
            f"ip -4 route add default dev {iface} table {table}",
            f"ip -6 route add default dev {iface} table {table}",
            f"ip -4 rule add not to {gateway} table {table}",
            f"ip -6 rule add table {table}",
        ]
        _remove_wg_client()
        try:
            _client_exec("\n".join(script), check=True)
            yield WireguardClient(vps_exec)
        finally:
            _remove_wg_client()

    return _connect


@pytest.fixture
def paired_client(
    netlane: NetlaneRunner, tmp_path, wg_client
) -> Generator[WireguardClient, None, None]:
    """Pairs the profile and connects a WireGuard client with its client config."""
    client_conf_path = tmp_path / "paired_client.conf"
    netlane.pair("jailed", save_path=client_conf_path, force=True)
    with wg_client(client_conf_path.read_text()) as client:
        yield client
