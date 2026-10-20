import os
import queue
import re
import shlex
import signal
import socket
import subprocess
import sys
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Generator, Optional

import pytest

from netlane import APP_NAME
from netlane.config import Config, load_config
from netlane.modes import wireguard_ssh_reverse

TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent.parent

# The services of compose.yml, reached by name on its network.
VPS_HOST = "vps"
VPS_USER = "ubuntu"
CLIENT_HOST = "client"
REMOTE_HOST = "remote"
ADB_SERIAL = "redroid:5555"
# Redroid's adbd runs as the shell user and ships su.
ADB_ELEVATION = "su"

CLIENT_WG_IFACE = "wgclient"
# Routing table holding the client's default routes into the tunnel.
CLIENT_ROUTE_TABLE = 51820

# Stands in for the placeholder app of the shipped rooted profile.
# It runs as the ADB shell's uid, so traffic sent from an unelevated shell is that app's traffic.
ROOTED_APP = "com.android.shell"

START_HINT = (
    "Run the tests inside the integration test environment: "
    "docker compose -f tests/integration/compose.yml run --rm --build runner"
)
# Set by compose.yml for the runner service.
IN_TEST_ENVIRONMENT = os.environ.get("IN_TEST_ENVIRONMENT") == "1"


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Skips the integration tests outside the integration test environment, where their services do not exist."""
    if IN_TEST_ENVIRONMENT:
        return
    skip = pytest.mark.skip(reason=START_HINT)
    for item in items:
        if item.get_closest_marker("integration"):
            item.add_marker(skip)


def _ssh(host: str, script: str, check: bool = False) -> subprocess.CompletedProcess:
    """Runs `script` with sh on a service of the stack."""
    return subprocess.run(
        ["ssh", host, "sh", "-s"],
        input=script,
        capture_output=True,
        text=True,
        check=check,
    )


def _service_address(host: str) -> str:
    """Address of a service on the stack's network. Fails the test if it is not running."""
    try:
        return socket.gethostbyname(host)
    except OSError:
        pytest.fail(f"Service '{host}' is not running. {START_HINT}")


@pytest.fixture(scope="session")
def vps_server() -> None:
    """Checks that the VPS accepts the stack's key over SSH."""
    res = subprocess.run(
        ["ssh", "-o", "ConnectTimeout=5", f"{VPS_USER}@{VPS_HOST}", "true"],
        capture_output=True,
        text=True,
    )
    if res.returncode != 0:
        pytest.fail(
            f"SSH to {VPS_USER}@{VPS_HOST} failed: {res.stderr.strip()}. {START_HINT}"
        )


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

    def _cmd(self, *args: str) -> list[str]:
        """The CLI with the configured config path and `args`."""
        return [
            sys.executable,
            "-m",
            APP_NAME,
            "--config",
            str(self.config_path),
            *args,
        ]

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
        """Runs the CLI with the given arguments."""
        return self._run_cmd(self._cmd(*args), input_data=stdin, check=check)

    def setup(
        self, profile: str, distro: str = "ubuntu", check: bool = True
    ) -> subprocess.CompletedProcess:
        """Runs the `setup` step, answering its confirmation prompt."""
        profile_obj = self.config.profiles.get(profile)
        if profile_obj is None:
            raise ValueError(f"Profile {profile} not found in config")

        ssh_target = (
            f"{profile_obj.mode_opts.ssh_user}@{profile_obj.mode_opts.ssh_host}"
        )
        cmd = self._cmd("-v", "setup", profile, "--distro", distro)
        return self._run_cmd(cmd, input_data=f"{ssh_target}\n", check=check)

    def pair(
        self,
        profile: str,
        save_path: Optional[Path] = None,
        force: bool = True,
        check: bool = True,
    ) -> subprocess.CompletedProcess:
        """Runs the `pair` step."""
        cmd = self._cmd("-v", "pair", profile)
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
        Runs the `up` step as a background process and interrupts it on context exit.

        Leaving the context sends Ctrl-C and requires `up` to tear down on its own
        and exit cleanly. `down` only runs as a fallback when something failed,
        so that a broken teardown is not hidden and later tests start clean.
        Without `check`, `up` may exit with any code, e.g. when a test ended it.
        """
        proc = subprocess.Popen(
            self._cmd("-v", "up", profile),
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
                if eof:
                    # Nothing left to read, wait for the exit itself.
                    try:
                        proc.wait(timeout=deadline - time.monotonic())
                    except subprocess.TimeoutExpired:
                        pass
                else:
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
                raise RuntimeError(f"up {reason}:\n{''.join(output)}")
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
            raise RuntimeError(f"up {reason} after Ctrl-C:\n{''.join(output)}")

    def down(self, profile: str, check: bool = True) -> subprocess.CompletedProcess:
        """Runs the `down` step."""
        return self._run_cmd(self._cmd("-v", "down", profile), check=check)


def _wireguard_config(
    profile: str = "jailed",
    rules: str = "",
    hooks: str = "",
    tunnels: str = "proxy_main = 8080",
) -> str:
    """Builds a config.toml with a wireguard_ssh_reverse profile for the test VPS."""
    return f"""[profiles.{profile}]
mode = "wireguard_ssh_reverse"

rules = [
{rules}
]

[profiles.{profile}.mode_opts]
ssh_host = "{VPS_HOST}"
ssh_user = "{VPS_USER}"
elevation = "sudo"
tunnels = {{ {tunnels} }}

[profiles.{profile}.hooks]
{hooks}
"""


@pytest.fixture(scope="session")
def wireguard_config(vps_server):
    """Factory fixture building wireguard_ssh_reverse configs with custom rules, hooks or tunnels."""
    return _wireguard_config


@pytest.fixture(scope="session")
def setup_vps(vps_server, tmp_path_factory):
    """Provisions the VPS once per test session."""
    cfg = tmp_path_factory.mktemp("cfg") / "config.toml"
    cfg.write_text(_wireguard_config())
    return NetlaneRunner(cfg).setup("jailed")


@pytest.fixture
def integration_config(tmp_path, setup_vps) -> Path:
    """Generates a temporary config.toml pointing to the test VPS."""
    config_file = tmp_path / "config.toml"
    config_file.write_text(
        _wireguard_config(
            rules="""
  { name = "Reject IPv6", saddr = ["::/0"], target = "action:reject" },
  { name = "Redirect HTTP", protocol = ["tcp"], dport = [80], target = "tunnel:proxy_main" },
  { name = "Default Route", target = "action:passthrough" },
""",
            hooks='pre_up = ""\npost_down = ""',
        )
    )
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
    """Connects ADB to the Android container and waits until it has booted."""
    _service_address(ADB_SERIAL.partition(":")[0])
    deadline = time.time() + 180
    while time.time() < deadline:
        # adbd only listens once Android is up.
        subprocess.run(["adb", "connect", ADB_SERIAL], capture_output=True, text=True)
        res = _adb("shell", "-n", "getprop sys.boot_completed", timeout=10)
        if res.returncode == 0 and res.stdout.strip() == "1":
            return {"serial": ADB_SERIAL, "elevation": ADB_ELEVATION}
        time.sleep(2)
    pytest.fail(
        f"Android device at {ADB_SERIAL} did not finish booting. "
        "Redroid needs binder in the Docker host's kernel: "
        "sudo modprobe binder_linux devices=binder,hwbinder,vndbinder"
    )


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
            res = _ssh(REMOTE_HOST, "cat /received", check=True)
            records = [line.split(" ", 2) for line in res.stdout.splitlines()]
            peers = [r[1] for r in records if [r[0], r[2]] == [endpoint, payload]]
            if peers or time.monotonic() >= deadline:
                return peers
            time.sleep(0.2)


@pytest.fixture(scope="session")
def remote() -> Remote:
    """The remote container."""
    return Remote(_service_address(REMOTE_HOST))


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
    return _ssh(CLIENT_HOST, script, check)


def _remove_wg_client() -> None:
    # Deleting the interface also removes the routes into it.
    _client_exec(f"ip link del {CLIENT_WG_IFACE}")
    for family in ("-4", "-6"):
        _client_exec(f"ip {family} rule del table {CLIENT_ROUTE_TABLE}")
    _client_exec('ip -4 rule del to "${SSH_CLIENT%% *}" lookup main')


@pytest.fixture(scope="session")
def wg_client(vps_exec):
    """
    Factory for a WireGuard client connected with a client config from `pair`.

    The client is a container of its own, standing in for the mobile device. It
    reaches the gateway's WireGuard port over the network and routes everything
    else through the tunnel, as the WireGuard app does with `AllowedIPs` of all.
    """
    _service_address(CLIENT_HOST)
    # The client config has the name the tests reach the VPS by.
    # The client is on the VPS's network and uses its address directly.
    gateway = _service_address(VPS_HOST)

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
            # Replies to the runner's ssh sessions stay out of the tunnel as well.
            'ip -4 rule add to "${SSH_CLIENT%% *}" lookup main',
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
