import re
import subprocess
from ipaddress import ip_network

import pytest

from netlane.config import AdbReverseOpts, Profile, Rule, Tunnel
from netlane.modes import adb_reverse as mode
from netlane.modes.interface import StepError

SERIAL = "emulator-5554"
PROFILE = Profile(
    mode="adb_reverse",
    rules=[
        Rule(
            name="App",
            protocol=["tcp"],
            dport=[443],
            app=["com.example.app"],
            target=Tunnel("main"),
        ),
    ],
    mode_opts=AdbReverseOpts(elevation="su", tunnels={"main": 8080}, serial=SERIAL),
    hooks={"pre_up": "echo pre_up", "pre_down": "echo pre", "post_down": "echo post"},
)


# adbd's fds, then /proc/net/tcp and tcp6 as seen on Redroid.
# Only inode 22594 is a listening adbd socket (port 0x15B3).
ADBD_SOCKETS = """\
socket:[22594]
socket:[54386]
/dev/null
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0B00007F:9549 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 21011 1 0000000000000000 100 0 0 10 0
   1: 00000000:17DF 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1002        0 23101 1 0000000000000000 100 0 0 10 0
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:15B3 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  2000        0 22594 1 0000000000000000 100 0 0 10 0
   1: 0000000000000000FFFF000014011EAC:15B3 0000000000000000FFFF00000202000A:9D24 01 00000000:00000000 00:00000000 00000000  2000        0 54386 2 0000000000000000 20 4 28 10 -1
"""


def done(stdout="", returncode=0, stderr=""):
    return subprocess.CompletedProcess([], returncode, stdout.encode(), stderr.encode())


class FakeProc:
    def __init__(self, wait_raises=None):
        self.wait_raises = wait_raises
        self.terminated = False

    def wait(self):
        if self.wait_raises and not self.terminated:
            raise self.wait_raises
        return 0

    def poll(self):
        return 0 if self.terminated else None

    def terminate(self):
        self.terminated = True


@pytest.fixture
def device(monkeypatch):
    """Device state seen by the adb calls. Tests adjust it before calling a step."""
    state = {
        "state": done("device"),
        "root": True,
        "up": False,
        "ipv6_nat": True,
        "reversed": "",
        "users": "Users:\n\tUserInfo{0:Owner:c13} running\n\tUserInfo{10:Work user:400}\n",
        "packages": {
            "0": "package:com.example.app uid:10123\npackage:com.example.app.debug uid:10124\n",
            "10": "package:com.example.app uid:1010123\n",
        },
        "adbd_sockets": ADBD_SOCKETS,
        "watcher": FakeProc(),
        "calls": [],
    }

    def run(serial, args, check=True):
        state["calls"].append(("run", serial, list(args)))
        if args == ["get-state"]:
            return state["state"]
        if args == ["reverse", "--list"]:
            return done(state["reversed"])
        return done()

    def shell(serial, cmd, check=True):
        state["calls"].append(("shell", serial, cmd))
        if cmd == "pm list users":
            return done(state["users"])
        user = cmd.removeprefix("cmd package list packages -U --user ")
        return done(state["packages"].get(user, ""))

    def run_script(serial, elevation, content, check=True):
        state["calls"].append(("script", serial, elevation, content))
        if content == "id -u":
            return done("0\n" if state["root"] else "2000\n")
        if "then echo up" in content:
            return done("up\n" if state["up"] else "")
        if "then echo yes" in content:
            return done("yes\n" if state["ipv6_nat"] else "")
        if "pidof adbd" in content:
            return done(state["adbd_sockets"])
        return done()

    def start(serial, args):
        state["calls"].append(("start", serial, list(args)))
        return state["watcher"]

    monkeypatch.setattr(mode.shutil, "which", lambda cmd: "/usr/bin/adb")
    monkeypatch.setattr(mode.adb, "run", run)
    monkeypatch.setattr(mode.adb, "shell", shell)
    monkeypatch.setattr(mode.adb, "run_script", run_script)
    monkeypatch.setattr(mode.adb, "start", start)
    return state


def scripts(state):
    return [c[3] for c in state["calls"] if c[0] == "script"]


def test_up_requires_local_adb(device, monkeypatch):
    monkeypatch.setattr(mode.shutil, "which", lambda cmd: None)
    with pytest.raises(StepError, match="'adb'.*not found"):
        mode.up("rooted", PROFILE)


@pytest.mark.parametrize(
    "state, message",
    [
        pytest.param(
            {"state": done(returncode=1, stderr="error: device not found")},
            "Device not available: error: device",
            id="no device",
        ),
        pytest.param({"up": True}, "Run 'down rooted' first", id="already up"),
        pytest.param(
            {"reversed": "emulator-5554 tcp:8080 tcp:9090\n"},
            "8080 already reversed",
            id="foreign reverse port",
        ),
        pytest.param(
            {"packages": {"0": "package:com.example.app.debug uid:10124\n"}},
            "'com.example.app' is not installed",
            id="app not installed",
        ),
        pytest.param({"users": ""}, "Could not list device users", id="no users"),
    ],
)
def test_up_refuses(device, state, message):
    device.update(state)
    with pytest.raises(StepError, match=message):
        mode.up("rooted", PROFILE)


@pytest.mark.parametrize("step", [mode.up, mode.down])
def test_step_refuses_non_root_shell_before_touching_device(device, step):
    device["root"] = False

    with pytest.raises(StepError, match="not root"):
        step("rooted", PROFILE)

    assert scripts(device) == ["id -u"]
    assert not any(c[2][0] == "reverse" for c in device["calls"] if c[0] == "run")


def test_up_without_ipv6_nat_refuses_ipv6_tunnel_rules(device, caplog):
    device["ipv6_nat"] = False
    with pytest.raises(StepError, match=r"'App' match IPv6.*0\.0\.0\.0/0"):
        mode.up("rooted", PROFILE)
    assert "IPv6 NAT rules cannot be applied" in caplog.text


def test_up_applies_rules_for_all_app_uids_then_tears_down_on_ctrl_c(device):
    device["watcher"] = FakeProc(wait_raises=KeyboardInterrupt)

    mode.up("rooted", PROFILE)

    applied = scripts(device)
    ruleset = next(s for s in applied if "iptables-restore" in s)
    assert "--uid-owner 10123 " in ruleset
    assert "--uid-owner 1010123 " in ruleset
    assert "--uid-owner 10124 " not in ruleset
    assert ("run", SERIAL, ["reverse", "--no-rebind", "tcp:8080", "tcp:8080"]) in (
        device["calls"]
    )
    assert device["watcher"].terminated
    assert ("run", SERIAL, ["reverse", "--remove", "tcp:8080"]) in device["calls"]
    assert applied[-3:-1] == [
        "echo pre",
        mode.remove_iptables_rules(mode.CHAIN_NAME),
    ]


def test_up_applies_rules_for_app_installed_only_for_secondary_user(device):
    device["packages"] = {"0": "", "10": "package:com.example.app uid:1010123\n"}
    device["watcher"] = FakeProc(wait_raises=KeyboardInterrupt)

    mode.up("rooted", PROFILE)

    ruleset = next(s for s in scripts(device) if "iptables-restore" in s)
    assert "--uid-owner 1010123 " in ruleset
    assert "--uid-owner 10123 " not in ruleset


@pytest.mark.parametrize(
    "adbd_sockets, exempt",
    [
        pytest.param(ADBD_SOCKETS, ["5555"], id="network"),
        pytest.param("socket:[22594]\n", [], id="usb only"),
    ],
)
def test_up_exempts_replies_of_adbd_listen_ports(device, adbd_sockets, exempt):
    device["adbd_sockets"] = adbd_sockets
    device["watcher"] = FakeProc(wait_raises=KeyboardInterrupt)

    mode.up("rooted", PROFILE)

    ruleset = next(s for s in scripts(device) if "iptables-restore" in s)
    assert re.findall(r"--sport (\d+) -m conntrack --ctdir REPLY", ruleset) == (
        exempt * 2
    )


def test_up_without_ipv6_nat_applies_ipv4_only_tunnels(device, caplog):
    device["ipv6_nat"] = False
    device["watcher"] = FakeProc(wait_raises=KeyboardInterrupt)
    profile = Profile(
        mode="adb_reverse",
        rules=[
            Rule(
                name="App",
                daddr=[ip_network("0.0.0.0/0")],
                protocol=["tcp"],
                dport=[443],
                app=["com.example.app"],
                target=Tunnel("main"),
            )
        ],
        mode_opts=PROFILE.mode_opts,
    )

    mode.up("rooted", profile)

    ruleset = next(s for s in scripts(device) if "iptables-restore" in s)
    ipv6_input = ruleset.split("ip6tables-restore")[1]
    assert "*nat" not in ipv6_input
    assert "IPv6 NAT rules cannot be applied" in caplog.text


def test_up_exits_without_teardown_on_disconnect(device):
    with pytest.raises(StepError, match="Device disconnected.*'down rooted'"):
        mode.up("rooted", PROFILE)

    assert "echo pre" not in scripts(device)


def test_up_tears_down_and_reraises_on_failure(device, monkeypatch):
    def failing_start(serial, args):
        raise subprocess.CalledProcessError(1, "adb")

    monkeypatch.setattr(mode.adb, "start", failing_start)

    with pytest.raises(subprocess.CalledProcessError):
        mode.up("rooted", PROFILE)

    assert mode.remove_iptables_rules(mode.CHAIN_NAME) in scripts(device)


def test_down_runs_hooks_around_teardown(device):
    mode.down("rooted", PROFILE)

    assert scripts(device) == [
        "id -u",
        "echo pre",
        mode.remove_iptables_rules(mode.CHAIN_NAME),
        "echo post",
    ]
    assert ("run", SERIAL, ["reverse", "--remove", "tcp:8080"]) in device["calls"]
