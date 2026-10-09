from ipaddress import ip_network

import pytest

from netlane import APP_NAME
from netlane.config import Action, AdbReverseOpts, Profile, Rule, Tunnel
from netlane.rulesets.iptables import (
    generate_iptables_rules,
    ipv6_tunnel_rules,
    remove_iptables_rules,
)

CHAIN = APP_NAME
OPTS = AdbReverseOpts(elevation="su", tunnels={"main": 8080, "telemetry": 8081})


def profile_of(rules):
    return Profile(mode="adb_reverse", rules=rules, mode_opts=OPTS)


def generate(rules, app_uids=None, adbd_ports=(), ipv6_nat=True):
    return generate_iptables_rules(
        profile_of(rules), CHAIN, app_uids or {}, list(adbd_ports), ipv6_nat
    )


def restore_input(family, nat_rules, filter_rules, nat=True):
    """The iptables-restore heredoc of one address family."""
    cmd = "iptables-restore" if family == 4 else "ip6tables-restore"
    nat_section = [
        "*nat",
        f":{CHAIN} - [0:0]",
        f"-I OUTPUT 1 -j {CHAIN}",
        f"-A {CHAIN} -o lo -j RETURN",
        *nat_rules,
        "COMMIT",
    ]
    return [
        f"{cmd} -w -n <<'EOF'",
        *(nat_section if nat else []),
        "*filter",
        f":{CHAIN} - [0:0]",
        f":{CHAIN}_input - [0:0]",
        f"-I OUTPUT 1 -j {CHAIN}",
        f"-I INPUT 1 -j {CHAIN}_input",
        f"-A {CHAIN} -o lo -j RETURN",
        f"-A {CHAIN} -m conntrack --ctstate DNAT -j RETURN",
        *filter_rules,
        f"-A {CHAIN} -j DROP",
        f"-A {CHAIN}_input ! -i lo -p tcp --dport 8080 -j DROP",
        f"-A {CHAIN}_input ! -i lo -p tcp --dport 8081 -j DROP",
        "COMMIT",
        "EOF",
    ]


def expected(nat_v4=(), filter_v4=(), nat_v6=(), filter_v6=(), ipv6_nat=True):
    return "\n".join(
        ["set -e"]
        + restore_input(4, nat_v4, filter_v4)
        + restore_input(6, nat_v6, filter_v6, nat=ipv6_nat)
    )


def test_empty_profile_drops_everything_and_protects_tunnel_ports():
    assert generate([]) == expected()


def test_adbd_replies_bypass_rules():
    rules = [Rule(name="All", target=Action.DROP)]
    drop_all = f'-A {CHAIN} -m comment --comment "All" -j DROP'
    filt = [
        f"-A {CHAIN} -p tcp --sport 5555 -m conntrack --ctdir REPLY -j RETURN",
        f"-A {CHAIN} -p tcp --sport 37099 -m conntrack --ctdir REPLY -j RETURN",
        drop_all,
    ]
    nat = [f'-A {CHAIN} -m comment --comment "All" -j RETURN']

    assert generate(rules, adbd_ports=[5555, 37099]) == expected(nat, filt, nat, filt)


def test_tunnel_dnats_tcp_to_loopback_per_family():
    """Filter resets matching connections that nat didn't redirect, i.e. ones opened before up."""
    rules = [Rule(name="HTTP", protocol=["tcp"], dport=[80], target=Tunnel("main"))]
    match = f'-A {CHAIN} -p tcp --dport 80 -m comment --comment "HTTP"'

    assert generate(rules) == expected(
        nat_v4=[f"{match} -j DNAT --to-destination 127.0.0.1:8080"],
        filter_v4=[f"{match} -j REJECT --reject-with tcp-reset"],
        nat_v6=[f"{match} -j DNAT --to-destination [::1]:8080"],
        filter_v6=[f"{match} -j REJECT --reject-with tcp-reset"],
    )


def test_actions_terminate_in_both_tables():
    """Every rule returns in nat, so an earlier reject/drop/passthrough wins over a later tunnel."""
    rules = [
        Rule(name="R", protocol=["udp"], target=Action.REJECT),
        Rule(name="D", protocol=["udp"], target=Action.DROP),
        Rule(name="P", protocol=["udp"], target=Action.PASSTHROUGH),
    ]
    nat = [
        f'-A {CHAIN} -p udp -m comment --comment "R" -j RETURN',
        f'-A {CHAIN} -p udp -m comment --comment "D" -j RETURN',
        f'-A {CHAIN} -p udp -m comment --comment "P" -j RETURN',
    ]
    filt = [
        f'-A {CHAIN} -p udp -m comment --comment "R" -j REJECT',
        f'-A {CHAIN} -p udp -m comment --comment "D" -j DROP',
        f'-A {CHAIN} -p udp -m comment --comment "P" -j RETURN',
    ]

    assert generate(rules) == expected(nat, filt, nat, filt)


def test_ipv4_address_restricts_rule_to_ipv4_script():
    rules = [Rule(name="R", daddr=[ip_network("1.1.1.1")], target=Action.REJECT)]
    match = f'-A {CHAIN} -d 1.1.1.1/32 -m comment --comment "R"'

    assert generate(rules) == expected(
        nat_v4=[f"{match} -j RETURN"], filter_v4=[f"{match} -j REJECT"]
    )


def test_ipv6_address_restricts_rule_to_ipv6_script():
    rules = [Rule(name="R", saddr=[ip_network("::/0")], target=Action.REJECT)]
    match = f'-A {CHAIN} -s ::/0 -m comment --comment "R"'

    assert generate(rules) == expected(
        nat_v6=[f"{match} -j RETURN"], filter_v6=[f"{match} -j REJECT"]
    )


def test_mixed_family_addresses_split_per_family():
    rules = [
        Rule(
            name="Mixed",
            daddr=[
                ip_network("192.0.2.1"),
                ip_network("10.0.0.0/8"),
                ip_network("2001:db8::/32"),
            ],
            target=Action.DROP,
        )
    ]

    lines = generate(rules).splitlines()

    assert (
        f'-A {CHAIN} -d 192.0.2.1/32,10.0.0.0/8 -m comment --comment "Mixed" -j DROP'
        in lines
    )
    assert f'-A {CHAIN} -d 2001:db8::/32 -m comment --comment "Mixed" -j DROP' in lines


@pytest.mark.parametrize(
    "match",
    [
        "-p udp --sport 5353 --dport 53",
        "-p udp --sport 5353 --dport 5353",
        "-p udp --sport 5354 --dport 53",
        "-p udp --sport 5354 --dport 5353",
    ],
)
def test_sport_and_dport_match_every_combination(match):
    rules = [
        Rule(
            name="mDNS",
            protocol=["udp"],
            sport=[5353, 5354],
            dport=[53, 5353],
            target=Action.DROP,
        )
    ]
    lines = generate(rules).splitlines()
    assert f'-A {CHAIN} {match} -m comment --comment "mDNS" -j DROP' in lines


@pytest.mark.parametrize("uid", [10011, 10123, 1010123])
def test_app_and_skuid_match_union_of_uids(uid):
    rules = [
        Rule(
            name="App",
            protocol=["tcp"],
            dport=[443],
            skuid=[10011],
            app=["com.example.app"],
            target=Tunnel("main"),
        )
    ]

    lines = generate(rules, {"com.example.app": [10123, 1010123]}).splitlines()

    assert (
        f'-A {CHAIN} -p tcp --dport 443 -m owner --uid-owner {uid} -m comment --comment "App" -j DNAT --to-destination 127.0.0.1:8080'
        in lines
    )


def test_wrong_mode_rejected():
    profile = Profile(mode="wireguard_ssh_reverse", mode_opts=OPTS)
    with pytest.raises(ValueError, match="only supports adb_reverse"):
        generate_iptables_rules(profile, CHAIN, {}, [], True)


def test_without_ipv6_nat_ipv6_has_filter_rules_only():
    rules = [
        Rule(name="No v6", saddr=[ip_network("::/0")], target=Action.REJECT),
        Rule(
            name="HTTP",
            daddr=[ip_network("0.0.0.0/0")],
            protocol=["tcp"],
            dport=[80],
            target=Tunnel("main"),
        ),
    ]
    http = f'-A {CHAIN} -d 0.0.0.0/0 -p tcp --dport 80 -m comment --comment "HTTP"'

    assert generate(rules, ipv6_nat=False) == expected(
        nat_v4=[f"{http} -j DNAT --to-destination 127.0.0.1:8080"],
        filter_v4=[f"{http} -j REJECT --reject-with tcp-reset"],
        filter_v6=[f'-A {CHAIN} -s ::/0 -m comment --comment "No v6" -j REJECT'],
        ipv6_nat=False,
    )


def test_without_ipv6_nat_rejects_ipv6_tunnel_rules():
    rules = [Rule(name="HTTP", dport=[80], target=Tunnel("main"))]
    with pytest.raises(ValueError, match="require IPv6 NAT"):
        generate(rules, ipv6_nat=False)


def test_ipv6_tunnel_rules_lists_tunnel_rules_matching_ipv6():
    """Tunnel rules without addresses match IPv6, even behind a rule rejecting all IPv6."""
    rules = [
        Rule(name="No v6", saddr=[ip_network("::/0")], target=Action.REJECT),
        Rule(name="Any", dport=[80], target=Tunnel("main")),
        Rule(name="v4", daddr=[ip_network("0.0.0.0/0")], target=Tunnel("main")),
        Rule(name="v6", daddr=[ip_network("2001:db8::/32")], target=Tunnel("main")),
        Rule(name="Pass", target=Action.PASSTHROUGH),
    ]
    assert ipv6_tunnel_rules(profile_of(rules)) == ["Any", "v6"]


@pytest.mark.parametrize("ipt", ["iptables -w", "ip6tables -w"])
def test_remove_deletes_every_chain_and_jump(ipt):
    lines = remove_iptables_rules(CHAIN).splitlines()

    for line in [
        f"{ipt} -t nat -D OUTPUT -j {CHAIN}",
        f"{ipt} -t nat -X {CHAIN}",
        f"{ipt} -D OUTPUT -j {CHAIN}",
        f"{ipt} -D INPUT -j {CHAIN}_input",
        f"{ipt} -X {CHAIN}",
        f"{ipt} -X {CHAIN}_input",
    ]:
        assert f"{line} 2>/dev/null" in lines


def test_remove_always_succeeds():
    assert remove_iptables_rules(CHAIN).splitlines()[-1] == "true"
