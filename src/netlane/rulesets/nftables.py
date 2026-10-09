from typing import Dict, Iterable, List, Optional, Tuple

from netlane.config import (
    Action,
    IPNetwork,
    Profile,
    Rule,
    Tunnel,
    WireguardSSHReverseOpts,
)

NFT_FAMILIES = {4: "ip", 6: "ip6"}


def generate_nft_rules(
    profile: Profile[WireguardSSHReverseOpts],
    table_name: str,
    wg_iface: str,
    client_subnet_v4: str,
    client_subnet_v6: str,
    wg_server_addr_v4: str,
    wg_server_addr_v6: str,
) -> str:
    """Compiles a wireguard_ssh_reverse profile into an nft script, ready for `nft -f`.

    Each chain lists the profile's rules in profile order, so the first matching rule wins.
    """
    if profile.mode != "wireguard_ssh_reverse":
        raise ValueError(
            f"nftables backend only supports wireguard_ssh_reverse, got {profile.mode}"
        )

    def nft_rule(chain: str, *parts: str, comment: Optional[str] = None) -> str:
        line = [f"add rule inet {table_name} {chain}", *filter(None, parts)]
        if comment:
            line.append(f'comment "{comment}"')
        return " ".join(line)

    iface = f'iifname "{wg_iface}"'
    client_subnets = {4: client_subnet_v4, 6: client_subnet_v6}
    server_addrs = {4: wg_server_addr_v4, 6: f"[{wg_server_addr_v6}]"}
    tunnel_ports = [
        (rule, profile.mode_opts.tunnels[rule.target.name])
        for rule in profile.rules
        if isinstance(rule.target, Tunnel)
    ]
    passthrough = [r for r in profile.rules if r.target == Action.PASSTHROUGH]

    # Every statement terminates, so a packet is claimed by its first matching rule.
    prerouting = [
        nft_rule("prerouting", iface, match, statement, comment=rule.name)
        for rule in profile.rules
        for match, statement in _prerouting(rule, profile.mode_opts, server_addrs)
    ]
    input_chain = [
        # Catches packets marked by action:reject, which can't reject in the nat hook.
        nft_rule("input", iface, "meta mark 1 reject"),
        # ct status dnat only admits connections a tunnel rule redirected,
        # not ones addressing the tunnel port directly.
        *(
            nft_rule(
                "input",
                iface,
                f"tcp dport {port}",
                "ct status dnat",
                "accept",
                comment=rule.name,
            )
            for rule, port in tunnel_ports
        ),
        # The input hook also sees other interfaces (e.g. SSH), so the
        # default deny is scoped to the WireGuard interface.
        nft_rule("input", iface, "drop"),
    ]
    forward = [
        nft_rule("forward", iface, "meta mark 1 reject"),
        nft_rule("forward", "ct state established,related accept"),
        *(
            nft_rule("forward", iface, match, "accept", comment=rule.name)
            for rule in passthrough
            for match in _matches(rule)
        ),
        # The base forward chain accepts all WireGuard traffic, so the
        # default deny for it lives here.
        nft_rule("forward", iface, "drop"),
    ]
    # masquerade needs an explicit family, so it is emitted per family.
    postrouting = [
        nft_rule(
            "postrouting",
            f"{NFT_FAMILIES[family]} saddr {client_subnets[family]}",
            _match(rule, family),
            "masquerade",
            comment=rule.name,
        )
        for rule in passthrough
        for family in rule.families
    ]

    return "\n".join(
        [
            f"add table inet {table_name}",
            f"flush table inet {table_name}",
            f"add chain inet {table_name} prerouting {{ type nat hook prerouting priority dstnat; }}",
            f"add chain inet {table_name} input {{ type filter hook input priority filter; }}",
            f"add chain inet {table_name} forward {{ type filter hook forward priority filter; }}",
            f"add chain inet {table_name} postrouting {{ type nat hook postrouting priority srcnat; }}",
            *prerouting,
            *input_chain,
            *forward,
            *postrouting,
        ]
    )


def remove_nft_rules(table_name: str) -> str:
    """Tears down everything generate_nft_rules created, as a single atomic op."""
    return f"destroy table inet {table_name}"


def _prerouting(
    rule: Rule, mode_opts: WireguardSSHReverseOpts, server_addrs: Dict[int, str]
) -> List[Tuple[str, str]]:
    """The (match, statement) pairs of a rule in the prerouting chain."""
    match rule.target:
        case Action.REJECT:
            # reject can't run in the nat hook, input and forward reject the mark.
            return [(match, "meta mark set 1 return") for match in _matches(rule)]
        case Action.DROP:
            return [(match, "drop") for match in _matches(rule)]
        case Action.PASSTHROUGH:
            return [(match, "return") for match in _matches(rule)]
        case Tunnel(name=name):
            # dnat needs an explicit family, so it is emitted per family.
            port = mode_opts.tunnels[name]
            return [
                (
                    _match(rule, family),
                    f"dnat {NFT_FAMILIES[family]} to {server_addrs[family]}:{port}",
                )
                for family in rule.families
            ]


def _matches(rule: Rule) -> List[str]:
    """Match clauses covering a rule. An nft rule matches addresses of one family only, so there is one per family of the rule's addresses."""
    if rule.saddr is None and rule.daddr is None:
        return [_l4_match(rule)]
    return [_match(rule, family) for family in rule.families]


def _match(rule: Rule, family: int) -> str:
    """The nft match clause of a rule, restricted to its addresses of `family`."""
    parts = []
    for direction, networks in (("saddr", rule.saddr), ("daddr", rule.daddr)):
        if networks is not None:
            addrs = (_render_network(n) for n in networks if n.version == family)
            parts.append(f"{NFT_FAMILIES[family]} {direction} {_set_or_single(addrs)}")
    return " ".join(filter(None, [*parts, _l4_match(rule)]))


def _l4_match(rule: Rule) -> str:
    """The nft match clause of a rule's protocol, ports and skuid."""
    parts = []
    has_ports = bool(rule.sport or rule.dport)
    if has_ports and rule.protocol and len(rule.protocol) == 1:
        # Ports of a single protocol are matched in its own header, e.g. tcp dport.
        header = rule.protocol[0]
    else:
        # Otherwise ports are matched in the generic transport header.
        header = "th"
        if rule.protocol:
            parts.append(f"meta l4proto {_set_or_single(rule.protocol)}")

    if rule.sport:
        parts.append(f"{header} sport {_set_or_single(str(p) for p in rule.sport)}")
    if rule.dport:
        parts.append(f"{header} dport {_set_or_single(str(p) for p in rule.dport)}")

    if rule.skuid:
        parts.append(f"meta skuid {_set_or_single(str(u) for u in rule.skuid)}")

    return " ".join(parts)


def _render_network(network: IPNetwork) -> str:
    return str(network.network_address) if network.num_addresses == 1 else str(network)


def _set_or_single(values: Iterable[str]) -> str:
    values = list(values)
    if len(values) == 1:
        return values[0]
    return "{ " + ", ".join(values) + " }"
