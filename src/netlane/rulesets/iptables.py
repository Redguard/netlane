import itertools
from typing import Dict, List, Tuple

from netlane.config import Action, AdbReverseOpts, Profile, Rule, Target, Tunnel

FAMILIES = (4, 6)
RESTORE_CMDS = {4: "iptables-restore", 6: "ip6tables-restore"}
IPTABLES_CMDS = {4: "iptables", 6: "ip6tables"}
LOOPBACK_ADDRS = {4: "127.0.0.1", 6: "[::1]"}


def generate_iptables_rules(
    profile: Profile[AdbReverseOpts],
    chain_name: str,
    app_uids: Dict[str, List[int]],
    adbd_ports: List[int],
    ipv6_nat: bool,
) -> str:
    """Compiles an adb_reverse profile into a shell script loading the rules of both address families via iptables-restore.

    Rules match locally generated traffic in nat and filter OUTPUT. Packets matching no rule are dropped.
    `app_uids` maps each package of the profile's app rules to its uids.
    adbd's replies on `adbd_ports` are exempt from the rules, so ADB over the network keeps working.
    Without `ipv6_nat`, the IPv6 rules have no nat table and the profile must not have tunnel rules matching IPv6.
    """
    if profile.mode != "adb_reverse":
        raise ValueError(
            f"iptables backend only supports adb_reverse, got {profile.mode}"
        )
    if not ipv6_nat and ipv6_tunnel_rules(profile):
        raise ValueError("Tunnel rules matching IPv6 require IPv6 NAT")

    def iptables_rule(match: str, target: str, comment: str) -> str:
        parts = [f"-A {chain_name}", match, f'-m comment --comment "{comment}"']
        return " ".join([*filter(None, parts), f"-j {target}"])

    tunnels = profile.mode_opts.tunnels
    nat_rules: Dict[int, List[str]] = {family: [] for family in FAMILIES}
    filter_rules: Dict[int, List[str]] = {family: [] for family in FAMILIES}
    for rule in profile.rules:
        for family in rule.families:
            nat_target, filter_target = _targets(rule.target, family, tunnels)
            for match in _matches(rule, family, app_uids):
                nat_rules[family].append(iptables_rule(match, nat_target, rule.name))
                filter_rules[family].append(
                    iptables_rule(match, filter_target, rule.name)
                )

    ports = sorted(set(tunnels.values()))
    script = ["set -e"]
    for family in FAMILIES:
        script += [
            f"{RESTORE_CMDS[family]} -w -n <<'EOF'",
            *(
                _nat_table(chain_name, nat_rules[family])
                if family == 4 or ipv6_nat
                else []
            ),
            *_filter_table(chain_name, filter_rules[family], ports, adbd_ports),
            "EOF",
        ]
    return "\n".join(script)


def remove_iptables_rules(chain_name: str) -> str:
    """Returns a shell script removing everything generate_iptables_rules created. Succeeds when nothing is present."""
    input_chain = _input_chain(chain_name)
    script = []
    for family in FAMILIES:
        ipt = f"{IPTABLES_CMDS[family]} -w"
        script += [
            f"{ipt} -t nat -D OUTPUT -j {chain_name}",
            f"{ipt} -t nat -F {chain_name}",
            f"{ipt} -t nat -X {chain_name}",
            f"{ipt} -D OUTPUT -j {chain_name}",
            f"{ipt} -D INPUT -j {input_chain}",
            f"{ipt} -F {chain_name}",
            f"{ipt} -X {chain_name}",
            f"{ipt} -F {input_chain}",
            f"{ipt} -X {input_chain}",
        ]
    return "\n".join([f"{line} 2>/dev/null" for line in script] + ["true"])


def ipv6_tunnel_rules(profile: Profile[AdbReverseOpts]) -> List[str]:
    """Names of the profile's tunnel rules that match IPv6 traffic."""
    return [
        rule.name
        for rule in profile.rules
        if isinstance(rule.target, Tunnel) and 6 in rule.families
    ]


def _input_chain(chain_name: str) -> str:
    return f"{chain_name}_input"


def _nat_table(chain_name: str, rules: List[str]) -> List[str]:
    return [
        "*nat",
        f":{chain_name} - [0:0]",
        f"-I OUTPUT 1 -j {chain_name}",
        f"-A {chain_name} -o lo -j RETURN",
        *rules,
        "COMMIT",
    ]


def _filter_table(
    chain_name: str, rules: List[str], ports: List[int], adbd_ports: List[int]
) -> List[str]:
    input_chain = _input_chain(chain_name)
    return [
        "*filter",
        f":{chain_name} - [0:0]",
        f":{input_chain} - [0:0]",
        f"-I OUTPUT 1 -j {chain_name}",
        f"-I INPUT 1 -j {input_chain}",
        f"-A {chain_name} -o lo -j RETURN",
        # filter OUTPUT sees packets after nat rewrote them to a tunnel port.
        f"-A {chain_name} -m conntrack --ctstate DNAT -j RETURN",
        *(
            f"-A {chain_name} -p tcp --sport {p} -m conntrack --ctdir REPLY -j RETURN"
            for p in adbd_ports
        ),
        *rules,
        f"-A {chain_name} -j DROP",
        # adbd listens on all addresses, the tunnels are for the device only.
        *(f"-A {input_chain} ! -i lo -p tcp --dport {p} -j DROP" for p in ports),
        "COMMIT",
    ]


def _targets(target: Target, family: int, tunnels: Dict[str, int]) -> Tuple[str, str]:
    """The (nat, filter) targets of a rule. Both terminate, so the first matching rule wins in either table."""
    match target:
        case Action.REJECT:
            return "RETURN", "REJECT"
        case Action.DROP:
            return "RETURN", "DROP"
        case Action.PASSTHROUGH:
            return "RETURN", "RETURN"
        case Tunnel(name=name):
            # Tunneled packets returned earlier via ctstate DNAT.
            # So filter only sees connections opened before the rules, which nat no longer redirects.
            # Resetting them makes the app reconnect through the tunnel.
            return (
                f"DNAT --to-destination {LOOPBACK_ADDRS[family]}:{tunnels[name]}",
                "REJECT --reject-with tcp-reset",
            )


def _matches(rule: Rule, family: int, app_uids: Dict[str, List[int]]) -> List[str]:
    """The iptables match clauses of a rule, one per protocol, port and uid combination."""
    addrs = [
        f"{flag} {','.join(str(n) for n in networks if n.version == family)}"
        for flag, networks in (("-s", rule.saddr), ("-d", rule.daddr))
        if networks is not None
    ]

    uids = set(rule.skuid or [])
    for app in rule.app or []:
        uids.update(app_uids[app])

    matches = []
    for protocol, sport, dport, uid in itertools.product(
        rule.protocol or [None],
        rule.sport or [None],
        rule.dport or [None],
        sorted(uids) or [None],
    ):
        parts = [*addrs]
        if protocol:
            parts.append(f"-p {protocol}")
        if sport:
            parts.append(f"--sport {sport}")
        if dport:
            parts.append(f"--dport {dport}")
        if uid is not None:
            parts.append(f"-m owner --uid-owner {uid}")
        matches.append(" ".join(parts))
    return matches
