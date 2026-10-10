import subprocess
from pathlib import Path

import pytest

from netlane import remote

TARGET = "ubuntu@host.example.ch"
TMP = "/tmp/tmp.abc"


@pytest.fixture
def calls(monkeypatch):
    """Records the commands passed to run_cmd. mktemp returns TMP."""
    recorded = []

    def fake_run_cmd(cmd, capture_output=True, check=True, cwd=None):
        recorded.append(cmd)
        if cmd[0] == "scp":
            # The file name is relative to cwd.
            assert cwd is not None and (cwd / cmd[1]).is_file()
        stdout = f"{TMP}\n".encode() if cmd[-1] == "mktemp" else b""
        return subprocess.CompletedProcess(cmd, 0, stdout=stdout)

    monkeypatch.setattr(remote, "run_cmd", fake_run_cmd)
    return recorded


@pytest.mark.parametrize(
    "options, expected",
    [
        pytest.param({}, ["ssh", TARGET, "a && b"], id="plain"),
        pytest.param(
            {"elevation": "sudo", "tty": True},
            ["ssh", "-t", TARGET, "sudo sh -c 'a && b'"],
            id="elevated runs whole command elevated",
        ),
        pytest.param(
            {"elevation": "doas"},
            ["ssh", TARGET, "doas sh -c 'a && b'"],
            id="doas runs a shell",
        ),
        pytest.param(
            {"elevation": "su"},
            ["ssh", TARGET, "su -c 'a && b'"],
            id="su takes the command",
        ),
        pytest.param(
            {"elevation": ""},
            ["ssh", TARGET, "a && b"],
            id="empty elevation runs as is",
        ),
    ],
)
def test_run(calls, options, expected):
    remote.run(TARGET, "a && b", **options)
    assert calls == [expected]


def test_run_script_uploads_to_temp_file_runs_and_removes_it(calls):
    remote.run_script(TARGET, "sudo", "echo hi", ["bash"], ["192.0.2.1"])

    mktemp, scp, run = calls
    assert mktemp == ["ssh", TARGET, "mktemp"]
    assert scp[0] == "scp" and scp[2] == f"{TARGET}:{TMP}"
    # A bare file name, as some scp builds read a drive letter like C: as a host.
    assert scp[1] == Path(scp[1]).name
    assert run == [
        "ssh",
        "-t",
        TARGET,
        f"trap 'rm -f {TMP}' EXIT; sudo sh -c 'bash {TMP} 192.0.2.1'",
    ]


@pytest.mark.parametrize(
    "target, scp_target",
    [
        pytest.param(TARGET, f"{TARGET}:{TMP}", id="hostname"),
        pytest.param("ubuntu@2001:db8::1", f"ubuntu@[2001:db8::1]:{TMP}", id="ipv6"),
    ],
)
def test_upload_brackets_ipv6_host(calls, target, scp_target):
    remote.install_file(target, "sudo", "secret", "/etc/wireguard/wg0.conf")

    assert calls[1][2] == scp_target


def test_install_file_installs_root_only(calls):
    remote.install_file(TARGET, "sudo", "secret", "/etc/wireguard/wg0.conf")

    assert calls[-1][-1] == (
        f"trap 'rm -f {TMP}' EXIT; "
        f"sudo sh -c 'install -m 600 -o root -g root {TMP} /etc/wireguard/wg0.conf'"
    )
