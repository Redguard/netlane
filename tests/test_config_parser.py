from ipaddress import ip_network
from pathlib import Path

import pytest

from netlane.config import (
    Action,
    AdbReverseOpts,
    Config,
    MATCH_FIELDS,
    ConfigValidationError,
    Profile,
    Rule,
    Tunnel,
    WireguardSSHReverseOpts,
    load_config,
    parse_config_string,
)

ROOT_DIR = Path(__file__).resolve().parent.parent
RESOURCES_DIR = ROOT_DIR / "tests" / "resources"

ADB_OPTS = """
[profiles.test.mode_opts]
elevation = "su"
tunnels = { main = 8080 }
"""
WIREGUARD_OPTS = """
[profiles.test.mode_opts]
ssh_host = "h"
ssh_user = "u"
elevation = "sudo"
tunnels = { main = 8080 }
"""
MODE_OPTS = {"adb_reverse": ADB_OPTS, "wireguard_ssh_reverse": WIREGUARD_OPTS}
MODES = list(MODE_OPTS)


def profile_with_rules(mode, *rules):
    """A config of one profile in `mode` with the given TOML inline-table rules."""
    return f"""
[profiles.test]
mode = "{mode}"
rules = [{", ".join(rules)}]
{MODE_OPTS[mode]}
"""


def parse_rules(mode, *rules):
    return parse_config_string(profile_with_rules(mode, *rules)).profiles["test"].rules


@pytest.mark.parametrize(
    "toml_content, message",
    [
        pytest.param(
            """
            not_a_real_top_level_key = true

            [profiles.test]
            mode = "adb_reverse"

            [profiles.test.mode_opts]
            elevation = "su"
            tunnels = { main = 8080 }
            """,
            "unknown field.*root",
            id="root",
        ),
        pytest.param(
            """
            [profiles.test]
            mode = "adb_reverse"
            unknown_key = "should_fail"

            [profiles.test.mode_opts]
            elevation = "su"
            tunnels = { main = 8080 }
            """,
            "unknown field.*profile",
            id="profile",
        ),
        pytest.param(
            """
            [profiles.test]
            mode = "adb_reverse"

            [profiles.test.mode_opts]
            elevation = "su"
            tunnels = { main = 8080 }
            extra_bogus_opt = "nope"
            """,
            "unknown field",
            id="mode_opts",
        ),
        pytest.param(
            profile_with_rules(
                "adb_reverse",
                '{ name = "R", target = "action:drop", made_up_field = "x" }',
            ),
            "unknown field",
            id="rule",
        ),
    ],
)
def test_unknown_field_rejected(toml_content, message):
    with pytest.raises(ConfigValidationError, match=f"(?i){message}"):
        parse_config_string(toml_content)


@pytest.mark.parametrize(
    "field",
    [
        pytest.param('saddr = ["not-an-ip"]', id="invalid address"),
        pytest.param("dport = [70000]", id="port out of range"),
        pytest.param("skuid = [-1]", id="negative uid"),
        pytest.param("dport = [true]", id="boolean port"),
        pytest.param('dport = ["80"]', id="string port"),
        pytest.param('protocol = ["tcp; drop"]', id="injected protocol"),
        pytest.param('protocol = ["-j ACCEPT"]', id="option as protocol"),
        pytest.param('protocol = ["TCP"]', id="uppercase protocol"),
        pytest.param('protocol = ["all"]', id="all protocols"),
        pytest.param('protocol = ["0"]', id="protocol number 0"),
        pytest.param('protocol = ["256"]', id="protocol number out of range"),
        pytest.param('protocol = ["٤٧"]', id="non-ascii protocol number"),
        pytest.param("protocol = [6]", id="integer protocol"),
        pytest.param("sport = [0]", id="sport out of range"),
    ],
)
def test_invalid_rule_value_rejected(field):
    with pytest.raises(ConfigValidationError):
        parse_rules("adb_reverse", f'{{ name = "R", {field}, target = "action:drop" }}')


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize(
    "name",
    [
        pytest.param("", id="empty"),
        pytest.param('R\\" accept', id="quote"),
        pytest.param("R\\nEOF\\nreboot", id="newline"),
        pytest.param("R\\\\", id="backslash"),
        pytest.param("R" * 129, id="too long"),
    ],
)
def test_invalid_rule_name_rejected(mode, name):
    with pytest.raises(ConfigValidationError, match="rule name"):
        parse_rules(mode, f'{{ name = "{name}", target = "action:drop" }}')


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("protocol", ["tcp", "udp"])
def test_tested_protocol_accepted_silently(mode, protocol, caplog):
    [rule] = parse_rules(
        mode, f'{{ name = "R", protocol = ["{protocol}"], target = "action:drop" }}'
    )
    assert rule.protocol == [protocol]
    assert not caplog.records


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("protocol", ["icmp", "ipv6-icmp", "sctp", "47", "255"])
def test_other_protocol_passed_through_with_warning(mode, protocol, caplog):
    [rule] = parse_rules(
        mode, f'{{ name = "R", protocol = ["{protocol}"], target = "action:drop" }}'
    )
    assert rule.protocol == [protocol]
    assert f"Protocol '{protocol}' is uncharted territory" in caplog.text


def test_ports_on_portless_protocol_passed_to_backend():
    """The backend decides whether a protocol has ports."""
    [rule] = parse_rules(
        "adb_reverse",
        '{ name = "R", protocol = ["icmp"], dport = [80], target = "action:drop" }',
    )
    assert rule.dport == [80]


OPTS_ARGS = {
    "adb_reverse": (AdbReverseOpts, {"elevation": "su", "tunnels": {"main": 8080}}),
    "wireguard_ssh_reverse": (
        WireguardSSHReverseOpts,
        {
            "ssh_host": "h",
            "ssh_user": "u",
            "elevation": "sudo",
            "tunnels": {"main": 8080},
        },
    ),
}


def mode_opts(mode, **overrides):
    """The mode_opts of `mode`, with `overrides` replacing valid defaults."""
    cls, args = OPTS_ARGS[mode]
    return cls(**(args | overrides))


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize(
    "tunnels",
    [
        pytest.param({"main": 0}, id="port out of range"),
        pytest.param({"main": True}, id="boolean port"),
        pytest.param({"main": "8080; id"}, id="string port"),
        pytest.param([8080], id="not a table"),
    ],
)
def test_invalid_tunnels_rejected(mode, tunnels):
    with pytest.raises(ValueError, match="port"):
        mode_opts(mode, tunnels=tunnels)


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("elevation", ["", "sudo", "doas", "su"])
def test_elevation_accepted(mode, elevation):
    assert mode_opts(mode, elevation=elevation).elevation == elevation


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("elevation", ["sudo -E", "sudo;id", "/usr/bin/sudo", "run0"])
def test_invalid_elevation_rejected(mode, elevation):
    with pytest.raises(ValueError, match="elevation"):
        mode_opts(mode, elevation=elevation)


@pytest.mark.parametrize(
    "host",
    ["vps", "vps.example.ch", "xn--bcher-kva.example", "203.0.113.5", "2001:db8::1"],
)
def test_ssh_host_accepted(host):
    assert mode_opts("wireguard_ssh_reverse", ssh_host=host).ssh_host == host


@pytest.mark.parametrize(
    "host",
    [
        pytest.param("", id="empty"),
        pytest.param("-oProxyCommand=id", id="option"),
        pytest.param("vps-.example.ch", id="label ends with dash"),
        pytest.param("vps\nPostUp = id", id="newline"),
        pytest.param("vps example", id="space"),
        pytest.param("fe80::1%eth0", id="zone index"),
        pytest.param("a" * 64 + ".ch", id="label too long"),
    ],
)
def test_invalid_ssh_host_rejected(host):
    with pytest.raises(ValueError, match="hostname"):
        mode_opts("wireguard_ssh_reverse", ssh_host=host)


@pytest.mark.parametrize(
    "user",
    [
        pytest.param("", id="empty"),
        pytest.param("-oProxyCommand=id", id="option"),
        pytest.param("root@evil", id="at sign"),
        pytest.param("Ubuntu", id="uppercase"),
        pytest.param("u" * 33, id="too long"),
    ],
)
def test_invalid_ssh_user_rejected(user):
    with pytest.raises(ValueError, match="SSH user"):
        mode_opts("wireguard_ssh_reverse", ssh_user=user)


def test_saddr_daddr_parse_into_ip_networks():
    [rule] = parse_rules(
        "adb_reverse",
        '{ name = "R", saddr = ["10.0.0.0/24", "fd00::/8"], daddr = ["::1", "1.1.1.1"], target = "action:drop" }',
    )

    assert rule.saddr == [ip_network("10.0.0.0/24"), ip_network("fd00::/8")]
    assert rule.daddr == [ip_network("::1"), ip_network("1.1.1.1")]


@pytest.mark.parametrize("action", list(Action), ids=lambda a: a.value)
def test_action_target_parses_into_action(action):
    [rule] = parse_rules(
        "adb_reverse", f'{{ name = "R", target = "action:{action.value}" }}'
    )
    assert rule.target == action


def test_tunnel_target_parses_into_tunnel():
    [rule] = parse_rules(
        "adb_reverse", '{ name = "R", protocol = ["tcp"], target = "tunnel:main" }'
    )
    assert rule.target == Tunnel("main")


@pytest.mark.parametrize("target", ["action:bogus", "tunnel:", "drop", ""])
def test_invalid_target_rejected(target):
    with pytest.raises(ConfigValidationError, match="(?i)not a valid target"):
        parse_rules("adb_reverse", f'{{ name = "R", target = "{target}" }}')


@pytest.mark.parametrize("mode", MODES)
def test_undefined_tunnel_rejected(mode):
    with pytest.raises(ConfigValidationError, match="(?i)target tunnel.*not defined"):
        parse_rules(mode, '{ name = "R", target = "tunnel:missing_tunnel" }')


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize(
    "protocol",
    [
        pytest.param("", id="missing"),
        pytest.param('protocol = ["udp"], ', id="udp"),
        pytest.param('protocol = ["tcp", "udp"], ', id="tcp and udp"),
    ],
)
def test_tunnel_target_requires_tcp_only(mode, protocol):
    """Tunnels only carry TCP."""
    with pytest.raises(ConfigValidationError, match="must match protocol tcp only"):
        parse_rules(
            mode, f'{{ name = "R", {protocol}dport = [443], target = "tunnel:main" }}'
        )


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize(
    "field",
    [
        pytest.param('saddr = "10.0.0.0/8"', id="saddr"),
        pytest.param('daddr = "1.1.1.1"', id="daddr"),
        pytest.param('protocol = "udp"', id="protocol"),
        pytest.param("sport = 5353", id="sport"),
        pytest.param("dport = 443", id="dport"),
        pytest.param("skuid = 10011", id="skuid"),
        pytest.param('app = "com.example.app"', id="app"),
    ],
)
def test_scalar_instead_of_list_rejected(mode, field):
    name = field.split()[0]
    with pytest.raises(ConfigValidationError, match=f"{name} must be a list"):
        parse_rules(mode, f'{{ name = "R", {field}, target = "action:drop" }}')


@pytest.mark.parametrize("mode", MODES)
def test_rule_after_catch_all_rejected(mode):
    with pytest.raises(ConfigValidationError, match="'Late' never matches"):
        parse_rules(
            mode,
            '{ name = "All", target = "action:passthrough" }',
            '{ name = "Late", protocol = ["udp"], target = "action:drop" }',
        )


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize(
    "hooks, message",
    [
        pytest.param('post-up = "id"', "not a valid hook", id="unknown name"),
        pytest.param("pre_up = 1", "must be a string", id="non-string command"),
    ],
)
def test_invalid_hooks_rejected(mode, hooks, message):
    toml_content = profile_with_rules(mode) + f"[profiles.test.hooks]\n{hooks}\n"
    with pytest.raises(ConfigValidationError, match=message):
        parse_config_string(toml_content)


@pytest.mark.parametrize("mode", MODES)
def test_non_table_hooks_rejected(mode):
    toml_content = profile_with_rules(mode).replace(
        f'mode = "{mode}"', f'mode = "{mode}"\nhooks = "id"'
    )
    with pytest.raises(ConfigValidationError, match="hooks must be a table"):
        parse_config_string(toml_content)


@pytest.mark.parametrize("mode", MODES)
def test_duplicate_tunnel_ports_rejected(mode):
    with pytest.raises(ValueError, match="distinct ports"):
        mode_opts(mode, tunnels={"a": 8080, "b": 8080})


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize(
    "addresses",
    [
        pytest.param('saddr = ["10.0.0.0/8"], daddr = ["::1"]', id="disjoint"),
        pytest.param(
            'saddr = ["10.0.0.0/24", "::/0"], daddr = ["1.1.1.1"]', id="partial"
        ),
    ],
)
def test_address_family_mismatch_rejected(mode, addresses):
    """saddr and daddr must cover the same families, otherwise part of the rule could never match."""
    with pytest.raises(ConfigValidationError, match="family mismatch"):
        parse_rules(mode, f'{{ name = "R", {addresses}, target = "action:drop" }}')


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("field", MATCH_FIELDS)
def test_empty_match_list_rejected(mode, field):
    """An empty list would compile to no match clause and match everything."""
    with pytest.raises(ConfigValidationError, match=f"{field} must not be empty"):
        parse_rules(mode, f'{{ name = "R", {field} = [], target = "action:drop" }}')


@pytest.mark.parametrize("mode", MODES)
def test_duplicate_rule_rejected(mode):
    """A copy-pasted rule is rejected rather than silently collapsed."""
    rule = '{ name = "Drop QUIC", protocol = ["udp"], dport = [443], target = "action:drop" }'
    with pytest.raises(ConfigValidationError, match="Duplicate rule"):
        parse_rules(mode, rule, rule)


@pytest.mark.parametrize("field", ['app = ["com.example.app"]', "skuid = [10011]"])
def test_owner_rejected_in_wireguard_mode(field):
    """The server can't tell apps apart, the WireGuard app selects them instead."""
    with pytest.raises(ConfigValidationError, match="WireGuard app"):
        parse_rules(
            "wireguard_ssh_reverse",
            f'{{ name = "App", {field}, target = "action:drop" }}',
        )


@pytest.mark.parametrize("field", ["sport = [53]", "dport = [53]"])
def test_ports_without_protocol_rejected_in_adb_mode(field):
    """iptables matches ports only behind a protocol."""
    with pytest.raises(ConfigValidationError, match="require a protocol"):
        parse_rules(
            "adb_reverse", f'{{ name = "DNS", {field}, target = "action:drop" }}'
        )


@pytest.mark.parametrize("field", ["sport = [53]", "dport = [53]"])
def test_ports_without_protocol_allowed_in_wireguard_mode(field):
    parse_rules(
        "wireguard_ssh_reverse", f'{{ name = "DNS", {field}, target = "action:drop" }}'
    )


@pytest.mark.parametrize(
    "addresses, families",
    [
        pytest.param({}, [4, 6], id="none"),
        pytest.param({"daddr": [ip_network("1.1.1.1")]}, [4], id="v4 daddr"),
        pytest.param({"saddr": [ip_network("::/0")]}, [6], id="v6 saddr"),
        pytest.param(
            {"saddr": [ip_network("::/0"), ip_network("10.0.0.0/8")]},
            [4, 6],
            id="dual-stack saddr",
        ),
    ],
)
def test_rule_families(addresses, families):
    """A rule matches the families of its addresses, both without addresses."""
    assert Rule(name="R", target=Action.DROP, **addresses).families == families


def test_adb_reverse_requires_elevation():
    toml_content = """
    [profiles.test]
    mode = "adb_reverse"

    [profiles.test.mode_opts]
    tunnels = { main = 8080 }
    """
    with pytest.raises(ConfigValidationError, match="elevation"):
        parse_config_string(toml_content)


@pytest.mark.parametrize(
    "toml_rule, expected",
    [
        pytest.param(
            '{ name = "R", protocol = ["tcp"], sport = [5000], dport = [80], saddr = ["10.0.0.1"], daddr = ["1.1.1.1"], skuid = [1000], target = "tunnel:main" }',
            Rule(
                name="R",
                target=Tunnel("main"),
                saddr=[ip_network("10.0.0.1")],
                daddr=[ip_network("1.1.1.1")],
                protocol=["tcp"],
                sport=[5000],
                dport=[80],
                skuid=[1000],
            ),
            id="all matchers",
        ),
        pytest.param(
            '{ name = "R", protocol = ["tcp"], app = ["com.example.app"], target = "tunnel:main" }',
            Rule(
                name="R",
                target=Tunnel("main"),
                protocol=["tcp"],
                app=["com.example.app"],
            ),
            id="app",
        ),
        pytest.param(
            '{ name = "R", target = "action:passthrough" }',
            Rule(
                name="R",
                target=Action.PASSTHROUGH,
                saddr=None,
                daddr=None,
                protocol=None,
                sport=None,
                dport=None,
                skuid=None,
                app=None,
            ),
            id="matchers default to None",
        ),
    ],
)
def test_rule_parses_into_dataclass(toml_rule, expected):
    assert parse_rules("adb_reverse", toml_rule) == [expected]


def test_root_config_template_parses():
    """The root config.toml stays parseable under the current schema."""
    config_path = ROOT_DIR / "config.toml"
    if not config_path.exists():
        pytest.skip("Root config.toml not found.")

    config = load_config(config_path)

    assert config.profiles
    for profile in config.profiles.values():
        expected_opts = {
            "wireguard_ssh_reverse": WireguardSSHReverseOpts,
            "adb_reverse": AdbReverseOpts,
        }[profile.mode]
        assert isinstance(profile.mode_opts, expected_opts)


def test_full_example_parses():
    config = load_config(RESOURCES_DIR / "full_example.toml")

    assert config == Config(
        profiles={
            "jailed": Profile(
                mode="wireguard_ssh_reverse",
                rules=[
                    Rule(
                        name="Reject IPv6 traffic",
                        target=Action.REJECT,
                        saddr=[ip_network("::/0")],
                    ),
                    Rule(
                        name="Reject QUIC to force tcp",
                        target=Action.REJECT,
                        protocol=["udp"],
                        dport=[443],
                    ),
                    Rule(
                        name="Bypass TLS Fingerprinting",
                        target=Action.PASSTHROUGH,
                        daddr=[ip_network("123.123.123.123")],
                        dport=[443],
                    ),
                    Rule(
                        name="Drop analytics",
                        target=Action.DROP,
                        protocol=["udp"],
                        dport=[1900, 5353],
                    ),
                    Rule(
                        name="Redirect HTTP(S)",
                        target=Tunnel("proxy_main"),
                        protocol=["tcp"],
                        dport=[80, 443],
                    ),
                    Rule(name="Default Route", target=Action.PASSTHROUGH),
                ],
                mode_opts=WireguardSSHReverseOpts(
                    ssh_host="xxxxxxxx.myfancydomain.ch",
                    ssh_user="ubuntu",
                    elevation="sudo",
                    tunnels={"proxy_main": 8080},
                ),
                hooks={
                    "pre_up": "",
                    "post_up": "systemd-run --collect --unit=wg-pcap tcpdump -i wg0 -w /var/tmp/wg0.pcap",
                    "pre_down": "systemctl stop wg-pcap || true",
                    "post_down": "",
                },
            ),
            "rooted": Profile(
                mode="adb_reverse",
                rules=[
                    Rule(
                        name="Reject IPv6 traffic",
                        target=Action.REJECT,
                        saddr=[ip_network("::/0")],
                    ),
                    Rule(
                        name="Reject QUIC to force tcp",
                        target=Action.REJECT,
                        protocol=["udp"],
                        dport=[443],
                    ),
                    Rule(
                        name="Drop traffic from a specific owner",
                        target=Action.DROP,
                        protocol=["udp"],
                        dport=[1900, 5353],
                    ),
                    Rule(
                        name="Telemetry Route",
                        target=Tunnel("telemetry"),
                        skuid=[10011],
                        protocol=["tcp"],
                        dport=[9999],
                    ),
                    Rule(
                        name="Redirect HTTP(S) for the app in scope",
                        target=Tunnel("main"),
                        protocol=["tcp"],
                        dport=[80, 443],
                        app=["com.example.app"],
                    ),
                    Rule(name="Default Route", target=Action.PASSTHROUGH),
                ],
                mode_opts=AdbReverseOpts(
                    elevation="su",
                    tunnels={"main": 8080, "telemetry": 8081},
                    serial="emulator-5554",
                ),
                hooks={},
            ),
        }
    )
