from ipaddress import ip_network
from pathlib import Path

import pytest

from netlane import APP_NAME
from netlane.config import (
    Action,
    Profile,
    Rule,
    Tunnel,
    WireguardSSHReverseOpts,
    load_config,
)
from netlane.rulesets.nftables import generate_nft_rules, remove_nft_rules

RESOURCES_DIR = Path(__file__).resolve().parent / "resources"
OPTS = WireguardSSHReverseOpts(
    ssh_host="test.local",
    ssh_user="test",
    elevation="sudo",
    tunnels={"main": 8080, "telemetry": 8081},
)
PARAMS = dict(
    table_name=APP_NAME,
    wg_iface="wg0",
    client_subnet_v4="10.10.10.0/24",
    client_subnet_v6="fd10:10:10::/64",
    wg_server_addr_v4="10.10.10.1",
    wg_server_addr_v6="fd10:10:10::1",
)


def generate(rules, **overrides):
    profile = Profile(mode="wireguard_ssh_reverse", rules=rules, mode_opts=OPTS)
    return generate_nft_rules(profile, **{**PARAMS, **overrides})


def expected_ruleset(
    table=APP_NAME, iface="wg0", prerouting=(), input=(), forward=(), postrouting=()
):
    """The nft script with the fixed chain setup around the profile's rules of each chain.

    input and forward first reject packets marked by action:reject, which
    can't reject in the nat-hooked prerouting chain. input and forward have no
    chain-wide policy since they also see other interfaces (e.g. the admin's
    SSH), so their default deny is an iface-scoped drop after the profile's rules.
    """
    return "\n".join(
        [
            f"add table inet {table}",
            f"flush table inet {table}",
            f"add chain inet {table} prerouting {{ type nat hook prerouting priority dstnat; }}",
            f"add chain inet {table} input {{ type filter hook input priority filter; }}",
            f"add chain inet {table} forward {{ type filter hook forward priority filter; }}",
            f"add chain inet {table} postrouting {{ type nat hook postrouting priority srcnat; }}",
            *prerouting,
            f'add rule inet {table} input iifname "{iface}" meta mark 1 reject',
            *input,
            f'add rule inet {table} input iifname "{iface}" drop',
            f'add rule inet {table} forward iifname "{iface}" meta mark 1 reject',
            f"add rule inet {table} forward ct state established,related accept",
            *forward,
            f'add rule inet {table} forward iifname "{iface}" drop',
            *postrouting,
        ]
    )


def test_empty_profile_only_sets_up_chains():
    assert generate([]) == expected_ruleset()


@pytest.mark.parametrize(
    "action, statement",
    [
        # reject can't run in the nat-hooked prerouting chain, input and forward reject the mark.
        pytest.param(Action.REJECT, "meta mark set 1 return", id="reject"),
        pytest.param(Action.DROP, "drop", id="drop"),
    ],
)
def test_blocking_action_terminates_prerouting(action, statement):
    assert generate([Rule(name="R", target=action)]) == expected_ruleset(
        prerouting=[
            f'add rule inet {APP_NAME} prerouting iifname "wg0" {statement} comment "R"'
        ],
    )


def test_passthrough_returns_forwards_and_masquerades_dual_stack():
    """Returning in prerouting gives passthrough precedence over later rules."""
    assert generate([Rule(name="Pass", target=Action.PASSTHROUGH)]) == expected_ruleset(
        prerouting=[
            f'add rule inet {APP_NAME} prerouting iifname "wg0" return comment "Pass"'
        ],
        forward=[
            f'add rule inet {APP_NAME} forward iifname "wg0" accept comment "Pass"'
        ],
        postrouting=[
            f'add rule inet {APP_NAME} postrouting ip saddr 10.10.10.0/24 masquerade comment "Pass"',
            f'add rule inet {APP_NAME} postrouting ip6 saddr fd10:10:10::/64 masquerade comment "Pass"',
        ],
    )


def test_tunnel_redirects_dual_stack():
    """inet tables need an explicit ip/ip6 dnat target, so a tunnel rule without addresses dnats per family."""
    rules = [Rule(name="T", protocol=["tcp"], dport=[80], target=Tunnel("main"))]

    assert generate(rules) == expected_ruleset(
        prerouting=[
            f'add rule inet {APP_NAME} prerouting iifname "wg0" tcp dport 80 dnat ip to 10.10.10.1:8080 comment "T"',
            f'add rule inet {APP_NAME} prerouting iifname "wg0" tcp dport 80 dnat ip6 to [fd10:10:10::1]:8080 comment "T"',
        ],
        input=[
            f'add rule inet {APP_NAME} input iifname "wg0" tcp dport 8080 ct status dnat accept comment "T"',
        ],
    )


def test_address_and_port_matching():
    rules = [
        Rule(name="Ports", protocol=["udp"], dport=[80, 443], target=Action.DROP),
        Rule(name="v6 saddr", saddr=[ip_network("::/0")], target=Action.REJECT),
        Rule(name="v4 daddr", daddr=[ip_network("1.1.1.1")], target=Action.PASSTHROUGH),
    ]

    assert generate(rules) == expected_ruleset(
        prerouting=[
            f'add rule inet {APP_NAME} prerouting iifname "wg0" udp dport {{ 80, 443 }} drop comment "Ports"',
            f'add rule inet {APP_NAME} prerouting iifname "wg0" ip6 saddr ::/0 meta mark set 1 return comment "v6 saddr"',
            f'add rule inet {APP_NAME} prerouting iifname "wg0" ip daddr 1.1.1.1 return comment "v4 daddr"',
        ],
        forward=[
            f'add rule inet {APP_NAME} forward iifname "wg0" ip daddr 1.1.1.1 accept comment "v4 daddr"',
        ],
        postrouting=[
            f'add rule inet {APP_NAME} postrouting ip saddr 10.10.10.0/24 ip daddr 1.1.1.1 masquerade comment "v4 daddr"',
        ],
    )


def test_mixed_family_addresses_split_per_family():
    """A packet is only ever one family, so each family gets its own nft rule."""
    rules = [
        Rule(
            name="Mixed",
            saddr=[ip_network("10.0.0.0/24"), ip_network("::/0")],
            target=Action.DROP,
        )
    ]

    assert generate(rules) == expected_ruleset(
        prerouting=[
            f'add rule inet {APP_NAME} prerouting iifname "wg0" ip saddr 10.0.0.0/24 drop comment "Mixed"',
            f'add rule inet {APP_NAME} prerouting iifname "wg0" ip6 saddr ::/0 drop comment "Mixed"',
        ],
    )


@pytest.mark.parametrize(
    "ports, match",
    [
        pytest.param(
            {"protocol": ["udp"], "sport": [5353], "dport": [53]},
            "udp sport 5353 udp dport 53",
            id="single protocol",
        ),
        pytest.param(
            {"protocol": ["tcp", "udp"], "sport": [5353, 5354]},
            "meta l4proto { tcp, udp } th sport { 5353, 5354 }",
            id="multiple protocols",
        ),
        pytest.param(
            {"sport": [5353], "dport": [53]},
            "th sport 5353 th dport 53",
            id="no protocol",
        ),
        pytest.param({"protocol": ["udp"]}, "meta l4proto udp", id="no ports"),
    ],
)
def test_port_matching(ports, match):
    ruleset = generate([Rule(name="R", target=Action.DROP, **ports)])

    assert ruleset == expected_ruleset(
        prerouting=[
            f'add rule inet {APP_NAME} prerouting iifname "wg0" {match} drop comment "R"'
        ],
    )


def test_earlier_rule_takes_precedence():
    """Every prerouting rule terminates, so a drop wins over a later tunnel even though they live in different chains."""
    rules = [
        Rule(name="Drop", protocol=["tcp"], dport=[80], target=Action.DROP),
        Rule(name="Tunnel", protocol=["tcp"], dport=[80], target=Tunnel("main")),
    ]

    assert generate(rules) == expected_ruleset(
        prerouting=[
            f'add rule inet {APP_NAME} prerouting iifname "wg0" tcp dport 80 drop comment "Drop"',
            f'add rule inet {APP_NAME} prerouting iifname "wg0" tcp dport 80 dnat ip to 10.10.10.1:8080 comment "Tunnel"',
            f'add rule inet {APP_NAME} prerouting iifname "wg0" tcp dport 80 dnat ip6 to [fd10:10:10::1]:8080 comment "Tunnel"',
        ],
        input=[
            f'add rule inet {APP_NAME} input iifname "wg0" tcp dport 8080 ct status dnat accept comment "Tunnel"',
        ],
    )


def test_custom_table_iface_and_subnets():
    rules = [
        Rule(name="Pass", target=Action.PASSTHROUGH),
        Rule(name="Tunnel", protocol=["tcp"], dport=[80], target=Tunnel("main")),
    ]

    ruleset = generate(
        rules,
        table_name="custom",
        wg_iface="wg7",
        client_subnet_v4="192.168.99.0/24",
        client_subnet_v6="fd00:dead:beef::/64",
    )

    assert ruleset == expected_ruleset(
        table="custom",
        iface="wg7",
        prerouting=[
            'add rule inet custom prerouting iifname "wg7" return comment "Pass"',
            'add rule inet custom prerouting iifname "wg7" tcp dport 80 dnat ip to 10.10.10.1:8080 comment "Tunnel"',
            'add rule inet custom prerouting iifname "wg7" tcp dport 80 dnat ip6 to [fd10:10:10::1]:8080 comment "Tunnel"',
        ],
        input=[
            'add rule inet custom input iifname "wg7" tcp dport 8080 ct status dnat accept comment "Tunnel"',
        ],
        forward=['add rule inet custom forward iifname "wg7" accept comment "Pass"'],
        postrouting=[
            'add rule inet custom postrouting ip saddr 192.168.99.0/24 masquerade comment "Pass"',
            'add rule inet custom postrouting ip6 saddr fd00:dead:beef::/64 masquerade comment "Pass"',
        ],
    )


def test_generation_is_deterministic():
    """`up` regenerates the ruleset on every run."""
    rules = [
        Rule(name="A", protocol=["tcp"], dport=[80], target=Tunnel("main")),
        Rule(name="B", protocol=["tcp"], dport=[81], target=Tunnel("main")),
    ]
    assert generate(rules) == generate(rules)


def test_legacy_equivalent_config():
    """The config format reproduces the formerly hardcoded proxy rules."""
    profile = load_config(RESOURCES_DIR / "legacy_equivalent.toml").profiles["legacy"]

    assert generate_nft_rules(profile, **PARAMS) == expected_ruleset(
        prerouting=[
            f'add rule inet {APP_NAME} prerouting iifname "wg0" tcp dport 80 dnat ip to 10.10.10.1:8080 comment "Redirect HTTP"',
            f'add rule inet {APP_NAME} prerouting iifname "wg0" tcp dport 80 dnat ip6 to [fd10:10:10::1]:8080 comment "Redirect HTTP"',
            f'add rule inet {APP_NAME} prerouting iifname "wg0" tcp dport 443 dnat ip to 10.10.10.1:8080 comment "Redirect HTTPS"',
            f'add rule inet {APP_NAME} prerouting iifname "wg0" tcp dport 443 dnat ip6 to [fd10:10:10::1]:8080 comment "Redirect HTTPS"',
            f'add rule inet {APP_NAME} prerouting iifname "wg0" return comment "Allow internet access for the mobile device"',
        ],
        input=[
            f'add rule inet {APP_NAME} input iifname "wg0" tcp dport 8080 ct status dnat accept comment "Redirect HTTP"',
            f'add rule inet {APP_NAME} input iifname "wg0" tcp dport 8080 ct status dnat accept comment "Redirect HTTPS"',
        ],
        forward=[
            f'add rule inet {APP_NAME} forward iifname "wg0" accept comment "Allow internet access for the mobile device"',
        ],
        postrouting=[
            f'add rule inet {APP_NAME} postrouting ip saddr 10.10.10.0/24 masquerade comment "Allow internet access for the mobile device"',
            f'add rule inet {APP_NAME} postrouting ip6 saddr fd10:10:10::/64 masquerade comment "Allow internet access for the mobile device"',
        ],
    )


def test_wrong_mode_rejected():
    profile = Profile(mode="adb_reverse", mode_opts=OPTS)
    with pytest.raises(ValueError, match="only supports wireguard_ssh_reverse"):
        generate_nft_rules(profile, **PARAMS)


def test_remove_destroys_the_whole_table():
    """Teardown is a single atomic destroy."""
    assert remove_nft_rules(table_name=APP_NAME) == f"destroy table inet {APP_NAME}"
