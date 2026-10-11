import subprocess
import sys
from pathlib import Path

import pytest

from netlane import cli
from netlane.cli import build_parser, list_profiles, run_step
from netlane.config import parse_config_string
from netlane.modes import adb_reverse, wireguard_ssh_reverse
from netlane.modes.interface import StepError

CONFIG_TOML = """
[profiles.jailed]
mode = "wireguard_ssh_reverse"

[profiles.jailed.mode_opts]
ssh_host = "host.example.ch"
ssh_user = "ubuntu"
elevation = "sudo"
tunnels = { main = 8080 }

[profiles.rooted]
mode = "adb_reverse"

[profiles.rooted.mode_opts]
elevation = "su"
tunnels = { main = 8080 }
"""
CONFIG = parse_config_string(CONFIG_TOML)


def parse(*argv):
    return build_parser().parse_args(argv)


@pytest.mark.parametrize(
    "argv, expected",
    [
        pytest.param(
            ["--config", "x.toml", "up", "jailed"],
            {"config": Path("x.toml"), "command": "up", "profile": "jailed"},
            id="config is a global option",
        ),
        pytest.param(
            ["pair", "jailed", "--save", "client.conf", "--force"],
            {"save": Path("client.conf"), "force": True},
            id="pair options",
        ),
        pytest.param(
            ["pair", "jailed"], {"save": None, "force": False}, id="pair defaults"
        ),
        pytest.param(
            ["setup", "jailed", "--distro", "ubuntu"],
            {"distro": "ubuntu"},
            id="setup options",
        ),
        pytest.param(["list"], {"command": "list"}, id="list takes no profile"),
        pytest.param(
            ["list"], {"verbose": False, "color": "auto"}, id="output defaults"
        ),
        pytest.param(
            ["-v", "--color", "never", "list"],
            {"verbose": True, "color": "never"},
            id="output options are global",
        ),
        pytest.param(
            ["--log", "run.jsonl", "up", "jailed"],
            {"log": Path("run.jsonl"), "command": "up", "profile": "jailed"},
            id="log takes a path",
        ),
        pytest.param(["list"], {"log": None}, id="no log by default"),
    ],
)
def test_parser(argv, expected):
    args = vars(parse(*argv))
    assert {key: args[key] for key in expected} == expected


@pytest.mark.parametrize(
    "argv, message",
    [
        pytest.param(["up", "missing"], "Profile 'missing' not found", id="unknown"),
        pytest.param(
            ["pair", "rooted"],
            r"Profile 'rooted' \(adb_reverse\) has no pair step\.",
            id="step not supported by mode",
        ),
    ],
)
def test_run_step_refuses(argv, message):
    with pytest.raises(StepError, match=message):
        run_step(parse(*argv), CONFIG)


def test_run_step_dispatches_to_mode_and_hints_next_step(monkeypatch, caplog):
    calls = []
    monkeypatch.setattr(
        wireguard_ssh_reverse,
        "pair",
        lambda name, profile, save, force: calls.append((name, save, force)),
    )
    caplog.set_level("INFO")

    run_step(parse("pair", "jailed", "--force"), CONFIG)

    assert calls == [("jailed", None, True)]
    assert "Next: up jailed" in caplog.text


def test_list_profiles_shows_mode_and_steps(capsys):
    list_profiles(CONFIG)
    assert capsys.readouterr().out.splitlines() == [
        "jailed  wireguard_ssh_reverse  setup → pair → up",
        "rooted  adb_reverse            up",
    ]


@pytest.fixture
def run_main(monkeypatch, tmp_path):
    """Runs `netlane <argv>` in-process against a config file with `content`."""

    def _run(*argv, content=CONFIG_TOML):
        config = tmp_path / "config.toml"
        if content is not None:
            config.write_text(content)
        # Logging stays as pytest set it up, so caplog sees the messages.
        monkeypatch.setattr(cli, "setup_logging", lambda *args: None)
        monkeypatch.setattr(sys, "argv", ["netlane", "--config", str(config), *argv])
        cli.main()

    return _run


def test_main_runs_command(run_main, capsys):
    run_main("list")
    assert "jailed  wireguard_ssh_reverse" in capsys.readouterr().out


@pytest.mark.parametrize(
    "content, message",
    [
        pytest.param("profiles = [", "Invalid TOML", id="invalid toml"),
        pytest.param("", "Missing required 'profiles' section", id="no profiles"),
        pytest.param(
            '[profiles.test]\nmode = "bogus"', "Unknown mode 'bogus'", id="unknown mode"
        ),
        pytest.param(None, "Failed to read file", id="missing file"),
    ],
)
def test_main_exits_with_error_on_invalid_config(run_main, caplog, content, message):
    with pytest.raises(SystemExit) as exit_info:
        run_main("list", content=content)

    assert exit_info.value.code == 1
    assert f"Failed to load config: {message}" in caplog.text


def test_main_exits_with_error_on_step_error(run_main, caplog):
    with pytest.raises(SystemExit) as exit_info:
        run_main("up", "missing")

    assert exit_info.value.code == 1
    assert "Profile 'missing' not found" in caplog.text


@pytest.mark.xfail(
    strict=True,
    raises=subprocess.CalledProcessError,
    reason="main() only catches StepError, a failed command ends in a traceback",
)
def test_main_exits_with_error_on_failed_command(run_main, monkeypatch):
    def failing_up(name, profile):
        raise subprocess.CalledProcessError(1, ["adb", "shell"])

    monkeypatch.setattr(adb_reverse, "up", failing_up)

    with pytest.raises(SystemExit) as exit_info:
        run_main("up", "rooted")

    assert exit_info.value.code == 1
