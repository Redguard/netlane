import io
import shlex
import shutil
import subprocess
from dataclasses import replace

import pytest

from netlane.config import Profile, WireguardSSHReverseOpts
from netlane.modes import wireguard_ssh_reverse as mode
from netlane.modes.interface import StepError
from netlane.modes.wireguard_ssh_reverse import _generate_configs, _tunnel_forward_args

TARGET = "ubuntu@host.example.ch"
SCRIPT = mode.DISTRO_SCRIPTS["ubuntu"]
PROFILE = Profile(
    mode="wireguard_ssh_reverse",
    mode_opts=WireguardSSHReverseOpts(
        ssh_host="host.example.ch",
        ssh_user="ubuntu",
        elevation="sudo",
        tunnels={"main": 8080},
    ),
    hooks={"pre_down": "echo pre", "post_down": "echo post"},
)


@pytest.fixture
def server(monkeypatch):
    """Server state seen by the step checks. Tests adjust it before calling a step."""
    state = {"set_up": True, "paired": True, "up": False}
    monkeypatch.setattr(mode, "_check_set_up", lambda t: state["set_up"])
    monkeypatch.setattr(mode, "_check_config_exists", lambda t, e, i: state["paired"])
    monkeypatch.setattr(mode, "_check_iface_up", lambda t, i: state["up"])
    return state


def test_confirm_install_continues_on_matching_target(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO(f"{TARGET}\n"))
    mode.confirm_install(TARGET, SCRIPT)
    assert "only accept SSH on port 22" in capsys.readouterr().err


@pytest.mark.parametrize(
    "stdin",
    [pytest.param("ubuntu@other\n", id="wrong target"), pytest.param("", id="empty")],
)
def test_confirm_install_aborts(monkeypatch, stdin):
    monkeypatch.setattr("sys.stdin", io.StringIO(stdin))
    with pytest.raises(StepError, match="Aborted."):
        mode.confirm_install(TARGET, SCRIPT)


@pytest.mark.parametrize(
    "state, message",
    [
        pytest.param({"set_up": False}, "Run 'setup jailed' first", id="not set up"),
        pytest.param(
            {"paired": False}, "Run 'pair jailed' to create them", id="not paired"
        ),
        pytest.param({"up": True}, "Run 'down jailed' first", id="already up"),
    ],
)
def test_up_refuses(server, state, message):
    server.update(state)
    with pytest.raises(StepError, match=message):
        mode.up("jailed", PROFILE)


@pytest.mark.parametrize(
    "state, force, message",
    [
        pytest.param(
            {"set_up": False}, False, "Run 'setup jailed' first", id="not set up"
        ),
        pytest.param({"up": True}, True, "Run 'down jailed' first", id="up"),
        pytest.param({}, False, "Use --force to replace its keys", id="paired"),
    ],
)
def test_pair_refuses(server, state, force, message):
    server.update(state)
    with pytest.raises(StepError, match=message):
        mode.pair("jailed", PROFILE, None, force=force)


def test_pair_with_force_replaces_keys(server, monkeypatch):
    deployed = []
    monkeypatch.setattr(mode.shutil, "which", lambda cmd: "/usr/bin/wg")
    monkeypatch.setattr(mode, "_generate_configs", lambda host: ("srv", "cli"))
    monkeypatch.setattr(
        mode, "_deploy_server_config", lambda *args: deployed.append(args[-1])
    )
    monkeypatch.setattr(mode, "_display_qr_code", lambda conf: None)

    mode.pair("jailed", PROFILE, None, force=True)

    assert deployed == ["srv"]


def test_down_runs_hooks_around_teardown(monkeypatch):
    calls = []
    monkeypatch.setattr(mode, "_run_hook", lambda t, e, cmd: calls.append(cmd))
    monkeypatch.setattr(mode, "_stop_wireguard", lambda *a: calls.append("stop"))
    monkeypatch.setattr(mode, "_teardown_nft", lambda *a: calls.append("nft"))
    monkeypatch.setattr(mode, "_flush_conntrack", lambda *a: calls.append("flush"))

    mode.down("jailed", PROFILE)

    assert calls == ["echo pre", "stop", "nft", "flush", "echo post"]


class FinishedProcess:
    def wait(self):
        return 0

    def poll(self):
        return 0


def test_up_flushes_conntrack_before_trusting_wireguard(server, monkeypatch):
    """Established connections bypass the rules, so none may survive into a session."""
    calls = []
    for name in (
        "_start_wireguard",
        "_apply_nft_script",
        "_flush_conntrack",
        "_register_trusted_iface",
        "_stop_wireguard",
        "_teardown_nft",
        "_run_hook",
    ):
        monkeypatch.setattr(mode, name, lambda *a, name=name: calls.append(name))
    monkeypatch.setattr(mode.remote, "start", lambda t, o: FinishedProcess())

    mode.up("jailed", PROFILE)

    assert [c for c in calls if c != "_run_hook"] == [
        "_start_wireguard",
        "_apply_nft_script",
        "_flush_conntrack",
        "_register_trusted_iface",
        "_stop_wireguard",
        "_teardown_nft",
        "_flush_conntrack",
    ]


@pytest.mark.parametrize(
    "exit_code, succeeds",
    [
        pytest.param(0, True, id="deleted"),
        pytest.param(1, True, id="nothing to delete"),
        pytest.param(2, False, id="error"),
        pytest.param(127, False, id="missing"),
    ],
)
def test_flush_conntrack_tolerates_nothing_to_delete(
    monkeypatch, tmp_path, exit_code, succeeds
):
    conntrack = tmp_path / "conntrack"
    conntrack.write_text(
        f'#!/bin/sh\necho "$@" >> {tmp_path}/calls\nexit {exit_code}\n'
    )
    conntrack.chmod(0o755)
    commands = []
    monkeypatch.setattr(
        mode.remote, "run", lambda t, cmd, *a, **k: commands.append(cmd)
    )

    mode._flush_conntrack(TARGET, "sudo")
    result = subprocess.run(
        ["sh", "-c", commands[0]], env={"PATH": f"{tmp_path}:/usr/bin:/bin"}
    )

    assert (result.returncode == 0) == succeeds
    calls = (tmp_path / "calls").read_text().splitlines()
    assert calls[0] == f"-D -f ipv4 -s {mode.CLIENT_SUBNET_V4}"
    if succeeds:
        assert calls[1] == f"-D -f ipv6 -s {mode.CLIENT_SUBNET_V6}"


@pytest.fixture
def ssh_commands(monkeypatch):
    """Records the commands the steps run against a server that is set up, paired and down."""
    commands = []

    def fake_run_cmd(cmd, capture_output=True, check=True, cwd=None):
        commands.append(cmd)
        stdout = b"/tmp/tmp.abc\n" if cmd[-1] == "mktemp" else b""
        returncode = 1 if cmd[-1].startswith("ip link show") else 0
        return subprocess.CompletedProcess(cmd, returncode, stdout=stdout)

    monkeypatch.setattr(mode.remote, "run_cmd", fake_run_cmd)
    monkeypatch.setattr(mode.remote, "start", lambda t, o: FinishedProcess())
    monkeypatch.setattr(mode, "_generate_keypair", lambda: ("priv", "pub"))
    monkeypatch.setattr(mode.shutil, "which", lambda cmd: "/usr/bin/wg")
    monkeypatch.setattr(mode, "_display_qr_code", lambda conf: None)
    monkeypatch.setattr("sys.stdin", io.StringIO(f"{TARGET}\n"))
    return commands


RUN_STEP = {
    "setup": lambda profile: mode.setup("jailed", profile, "ubuntu"),
    "pair": lambda profile: mode.pair("jailed", profile, None, force=True),
    "up": lambda profile: mode.up("jailed", profile),
    "down": lambda profile: mode.down("jailed", profile),
}


@pytest.mark.parametrize("elevation", ["sudo", "doas", "su"])
@pytest.mark.parametrize("step", mode.STEPS)
def test_elevated_commands_get_terminal(ssh_commands, step, elevation):
    """su and sudo can only prompt for a password in a terminal."""
    profile = replace(
        PROFILE,
        mode_opts=replace(PROFILE.mode_opts, elevation=elevation),
        hooks={hook: "true" for hook in ("pre_up", "post_up", "pre_down", "post_down")},
    )

    RUN_STEP[step](profile)

    elevated = [
        cmd
        for cmd in ssh_commands
        if cmd[0] == "ssh" and elevation in shlex.split(cmd[-1])
    ]
    assert elevated
    assert [cmd for cmd in elevated if "-t" not in cmd] == []


SHARED_VALUES = [mode.BASE_TABLE, mode.TRUSTED_IFACES_SET, str(mode.WG_LISTEN_PORT)]


def test_setup_passes_shared_values_to_script(ssh_commands):
    mode.setup("jailed", PROFILE, "ubuntu")

    script_cmd = shlex.split(shlex.split(ssh_commands[-1][-1])[-1])
    assert script_cmd == ["bash", "/tmp/tmp.abc", mode.APP_NAME, *SHARED_VALUES]


@pytest.mark.parametrize("value", SHARED_VALUES)
def test_script_does_not_hardcode_shared_values(value):
    assert value not in SCRIPT.read_text()


needs_wg = pytest.mark.skipif(shutil.which("wg") is None, reason="needs wg")


@needs_wg
def test_server_conf_is_dual_stack():
    """The server's tunnel address and its peer's allowed source range both cover IPv6."""
    server_conf, _ = _generate_configs("203.0.113.5")

    assert "Address = 10.10.10.1/24, fd10:10:10::1/64" in server_conf
    assert "AllowedIPs = 10.10.10.2/32, fd10:10:10::2/128" in server_conf


@needs_wg
def test_client_conf_is_dual_stack():
    """The client's tunnel address and default route both cover IPv6."""
    _, client_conf = _generate_configs("203.0.113.5")

    assert "Address = 10.10.10.2/24, fd10:10:10::2/64" in client_conf
    assert "AllowedIPs = 0.0.0.0/0, ::/0" in client_conf


@pytest.mark.parametrize(
    "host, endpoint",
    [
        pytest.param("vps.example.ch", "vps.example.ch:51820", id="hostname"),
        pytest.param("203.0.113.5", "203.0.113.5:51820", id="ipv4"),
        pytest.param("2001:db8::1", "[2001:db8::1]:51820", id="ipv6"),
    ],
)
def test_client_conf_endpoint(monkeypatch, host, endpoint):
    monkeypatch.setattr(mode, "_generate_keypair", lambda: ("priv", "pub"))

    _, client_conf = _generate_configs(host)

    assert f"Endpoint = {endpoint}\n" in client_conf


@pytest.mark.parametrize(
    "ports, expected",
    [
        pytest.param(
            [8080],
            [
                "-R",
                "10.10.10.1:8080:127.0.0.1:8080",
                "-R",
                "[fd10:10:10::1]:8080:[::1]:8080",
            ],
            id="one port",
        ),
        pytest.param(
            [8080, 8081],
            [
                "-R",
                "10.10.10.1:8080:127.0.0.1:8080",
                "-R",
                "[fd10:10:10::1]:8080:[::1]:8080",
                "-R",
                "10.10.10.1:8081:127.0.0.1:8081",
                "-R",
                "[fd10:10:10::1]:8081:[::1]:8081",
            ],
            id="two ports",
        ),
    ],
)
def test_tunnel_forward_args(ports, expected):
    """Each port binds on the server's tunnel address per family, forwarded to the local loopback of that family."""
    assert _tunnel_forward_args(ports, "10.10.10.1", "fd10:10:10::1") == expected
