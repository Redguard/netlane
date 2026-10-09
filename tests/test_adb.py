import subprocess

import pytest

from netlane import adb

SERIAL = "emulator-5554"
TMP = "/data/local/tmp/tmp.abc"


@pytest.fixture
def calls(monkeypatch):
    """Records the commands passed to run_cmd. mktemp returns TMP."""
    recorded = []

    def fake_run_cmd(cmd, capture_output=True, check=True):
        recorded.append(cmd)
        stdout = f"{TMP}\n".encode() if cmd[-1].startswith("mktemp") else b""
        return subprocess.CompletedProcess(cmd, 0, stdout=stdout)

    monkeypatch.setattr(adb, "run_cmd", fake_run_cmd)
    return recorded


@pytest.mark.parametrize(
    "serial, expected",
    [
        pytest.param(SERIAL, ["adb", "-s", SERIAL, "get-state"], id="serial"),
        pytest.param(None, ["adb", "get-state"], id="only device"),
    ],
)
def test_run_targets_device(calls, serial, expected):
    adb.run(serial, ["get-state"])
    assert calls == [expected]


def test_shell_does_not_read_stdin(calls):
    adb.shell(SERIAL, "cmd package list packages")
    assert calls == [["adb", "-s", SERIAL, "shell", "-n", "cmd package list packages"]]


def test_run_script_feeds_temp_file_to_root_shell_and_removes_it(calls):
    adb.run_script(SERIAL, "su", "iptables -S")

    mktemp, push, run = calls
    assert mktemp == [
        "adb",
        "-s",
        SERIAL,
        "shell",
        "-n",
        f"mktemp -p {adb.DEVICE_TMP_DIR}",
    ]
    assert push[3] == "push" and push[5] == TMP
    assert run == [
        "adb",
        "-s",
        SERIAL,
        "shell",
        "-n",
        f"trap 'rm -f {TMP}' EXIT; su < {TMP}",
    ]


def test_run_script_without_elevation_uses_plain_shell(calls):
    adb.run_script(None, "", "iptables -S")
    assert calls[-1][-1] == f"trap 'rm -f {TMP}' EXIT; sh < {TMP}"
