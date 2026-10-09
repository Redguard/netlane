from pathlib import Path

import pytest

from netlane.cli import build_parser, list_profiles, run_step
from netlane.config import parse_config_string
from netlane.modes import wireguard_ssh_reverse
from netlane.modes.interface import StepError

CONFIG = parse_config_string("""
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
""")


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
