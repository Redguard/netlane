import ipaddress
import logging
import re
import tomllib
from contextlib import suppress
from dataclasses import dataclass, field, fields
from enum import Enum
from typing import (
    TYPE_CHECKING,
    Any,
    Dict,
    Generic,
    List,
    Optional,
    Tuple,
    Type,
    TypeVar,
    Union,
)
from pathlib import Path

if TYPE_CHECKING:
    from _typeshed import DataclassInstance

logger = logging.getLogger(__name__)

IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

MIN_PORT, MAX_PORT = 1, 65535
MIN_UID, MAX_UID = 0, 2**32 - 2

# Other protocols are passed to iptables and nft as is, with a warning.
TESTED_PROTOCOLS = ("tcp", "udp")
ELEVATIONS = ("", "sudo", "doas", "su")
HOOKS = ("pre_up", "post_up", "pre_down", "post_down")
MATCH_FIELDS = ("saddr", "daddr", "protocol", "sport", "dport", "skuid", "app")

RULE_NAME = re.compile(r"[A-Za-z0-9 _.,:()/+-]{1,128}")
PROTOCOL_NAME = re.compile(r"[a-z][a-z0-9-]{0,31}")
MIN_PROTOCOL, MAX_PROTOCOL = 1, 255
SSH_USER = re.compile(r"[a-z_][a-z0-9_-]{0,31}")
HOSTNAME_LABEL = re.compile(r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)")
MAX_HOSTNAME_LENGTH = 253


class ConfigValidationError(Exception):
    """Exception raised for configuration validation errors."""

    pass


def _parse_network(value: Union[str, IPNetwork]) -> IPNetwork:
    if isinstance(value, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
        return value
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError as e:
        raise ValueError(f"{value!r} is not a valid IP address or network: {e}")


def _validate_range(value: int, low: int, high: int, label: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not (low <= value <= high)
    ):
        raise ValueError(f"{value!r} is not a valid {label} ({low}-{high})")
    return value


def _validate_pattern(value: str, pattern: re.Pattern, label: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ValueError(f"{value!r} is not a valid {label}")
    return value


def _validate_choice(value: str, choices: Tuple[str, ...], label: str) -> str:
    if value not in choices:
        raise ValueError(
            f"{value!r} is not a valid {label} ({', '.join(map(repr, choices))})"
        )
    return value


def _validate_protocol(value: str) -> str:
    """Accepts a protocol name or number. Excludes 0 and all, which iptables reads as every protocol."""
    if isinstance(value, str) and value.isascii() and value.isdigit():
        _validate_range(int(value), MIN_PROTOCOL, MAX_PROTOCOL, "protocol number")
    elif value == "all":
        raise ValueError("'all' is not a valid protocol. Omit protocol to match all")
    else:
        _validate_pattern(value, PROTOCOL_NAME, "protocol")
    if value not in TESTED_PROTOCOLS:
        logger.warning(
            f"Protocol {value!r} is uncharted territory and passed to iptables/nft as is. "
            "Manually verifying the ruleset is recommended."
        )
    return value


def _validate_host(value: str) -> str:
    """Accepts an RFC 1123 hostname or an IP address without a zone index."""
    if isinstance(value, str) and "%" not in value:
        if len(value) <= MAX_HOSTNAME_LENGTH and all(
            HOSTNAME_LABEL.fullmatch(label) for label in value.split(".")
        ):
            return value
        with suppress(ValueError):
            ipaddress.ip_address(value)
            return value
    raise ValueError(f"{value!r} is not a valid hostname or IP address")


def _validate_tunnels(value: Dict[str, int]) -> Dict[str, int]:
    if not isinstance(value, dict):
        raise ValueError("tunnels must be a table of names to ports")
    for port in value.values():
        _validate_range(port, MIN_PORT, MAX_PORT, "port")
    if len(set(value.values())) != len(value):
        raise ValueError("tunnels must use distinct ports")
    return value


def _validate_hooks(value: Dict[str, str]) -> Dict[str, str]:
    if not isinstance(value, dict):
        raise ValueError("hooks must be a table of hook names to commands")
    for name, cmd in value.items():
        _validate_choice(name, HOOKS, "hook")
        if not isinstance(cmd, str):
            raise ValueError(f"hook {name} must be a string")
    return value


class Action(Enum):
    REJECT = "reject"
    DROP = "drop"
    PASSTHROUGH = "passthrough"


@dataclass(frozen=True)
class Tunnel:
    name: str


Target = Union[Action, Tunnel]


def _parse_target(value: Union[str, Target]) -> Target:
    """Parses `action:<action>` or `tunnel:<name>`."""
    if isinstance(value, (Action, Tunnel)):
        return value
    kind, _, name = str(value).partition(":")
    if kind == "action" and name in {a.value for a in Action}:
        return Action(name)
    if kind == "tunnel" and name:
        return Tunnel(name)
    actions = ", ".join(f"action:{a.value}" for a in Action)
    raise ValueError(f"{value!r} is not a valid target ({actions} or tunnel:<name>)")


@dataclass
class Rule:
    name: str
    target: Target
    saddr: Optional[List[IPNetwork]] = None
    daddr: Optional[List[IPNetwork]] = None
    protocol: Optional[List[str]] = None
    sport: Optional[List[int]] = None
    dport: Optional[List[int]] = None
    skuid: Optional[List[int]] = None
    app: Optional[List[str]] = None

    def __post_init__(self):
        _validate_pattern(self.name, RULE_NAME, "rule name")
        self.target = _parse_target(self.target)
        for name in MATCH_FIELDS:
            value = getattr(self, name)
            if value is not None and not isinstance(value, list):
                raise ValueError(f"{name} must be a list, e.g. [{value!r}]")
            if value == []:
                raise ValueError(f"{name} must not be empty. Omit it to match all")
        if self.saddr is not None:
            self.saddr = [_parse_network(a) for a in self.saddr]
        if self.daddr is not None:
            self.daddr = [_parse_network(a) for a in self.daddr]
        if (
            self.saddr is not None
            and self.daddr is not None
            and _versions(self.saddr) != _versions(self.daddr)
        ):
            raise ValueError(
                "saddr/daddr family mismatch: both must cover the same address families"
            )
        if self.protocol is not None:
            self.protocol = [_validate_protocol(p) for p in self.protocol]
        if self.sport is not None:
            self.sport = [
                _validate_range(p, MIN_PORT, MAX_PORT, "port") for p in self.sport
            ]
        if self.dport is not None:
            self.dport = [
                _validate_range(p, MIN_PORT, MAX_PORT, "port") for p in self.dport
            ]
        if self.skuid is not None:
            self.skuid = [
                _validate_range(u, MIN_UID, MAX_UID, "uid") for u in self.skuid
            ]

    @property
    def families(self) -> List[int]:
        """The IP versions the rule matches: those of its addresses, both without addresses."""
        addrs = self.saddr or self.daddr
        return _versions(addrs) if addrs else [4, 6]

    @property
    def matches_all(self) -> bool:
        return all(getattr(self, name) is None for name in MATCH_FIELDS)


def _versions(networks: List[IPNetwork]) -> List[int]:
    return sorted({n.version for n in networks})


@dataclass
class WireguardSSHReverseOpts:
    ssh_host: str
    ssh_user: str
    elevation: str
    tunnels: Dict[str, int]

    def __post_init__(self):
        _validate_host(self.ssh_host)
        _validate_pattern(self.ssh_user, SSH_USER, "SSH user")
        _validate_choice(self.elevation, ELEVATIONS, "elevation")
        _validate_tunnels(self.tunnels)


@dataclass
class AdbReverseOpts:
    elevation: str
    tunnels: Dict[str, int]
    serial: Optional[str] = None

    def __post_init__(self):
        _validate_choice(self.elevation, ELEVATIONS, "elevation")
        _validate_tunnels(self.tunnels)


O = TypeVar("O", bound=Union[WireguardSSHReverseOpts, AdbReverseOpts])


@dataclass
class Profile(Generic[O]):
    mode: str
    mode_opts: O
    rules: List[Rule] = field(default_factory=list)
    hooks: Dict[str, str] = field(default_factory=dict)


@dataclass
class Config:
    profiles: Dict[str, Profile[Any]] = field(default_factory=dict)


T = TypeVar("T", bound="DataclassInstance")


def _from_dict(cls: Type[T], data: Any, context: str) -> T:
    """Instantiates a dataclass from a dict, strictly rejecting unknown keys."""
    if not isinstance(data, dict):
        raise ConfigValidationError(f"{context} must be a dictionary/table")

    allowed_keys = {f.name for f in fields(cls)}
    unknown_keys = set(data.keys()) - allowed_keys
    if unknown_keys:
        raise ConfigValidationError(
            f"Unknown field(s) found in {context}: {unknown_keys}"
        )

    try:
        return cls(**data)
    except (TypeError, ValueError) as e:
        raise ConfigValidationError(f"Invalid data in {context}: {e}")


def parse_config_string(toml_content: str) -> Config:
    """Parses a TOML configuration string and returns a Config object strictly."""
    try:
        data = tomllib.loads(toml_content)
    except Exception as e:
        raise ConfigValidationError(f"Invalid TOML: {e}")

    # Validate root
    unknown_keys = set(data.keys()) - {"profiles"}
    if unknown_keys:
        raise ConfigValidationError(
            f"Unknown field(s) found in root config: {unknown_keys}"
        )

    if "profiles" not in data:
        raise ConfigValidationError("Missing required 'profiles' section")

    profiles_data = data["profiles"]
    if not isinstance(profiles_data, dict):
        raise ConfigValidationError("'profiles' must be a table")

    parsed_profiles = {}
    for profile_id, profile_dict in profiles_data.items():
        if not isinstance(profile_dict, dict):
            raise ConfigValidationError(f"Profile '{profile_id}' must be a table")

        # Ensure no unknown keys at the profile level
        allowed_profile_keys = {f.name for f in fields(Profile)}
        unknown_keys = set(profile_dict.keys()) - allowed_profile_keys
        if unknown_keys:
            raise ConfigValidationError(
                f"Unknown field(s) found in profile '{profile_id}': {unknown_keys}"
            )

        mode = profile_dict.get("mode")
        if not mode:
            raise ConfigValidationError(f"Profile '{profile_id}' missing 'mode'")

        # Parse mode specific opts
        mode_opts_data = profile_dict.get("mode_opts", {})
        if mode == "wireguard_ssh_reverse":
            mode_opts = _from_dict(
                WireguardSSHReverseOpts,
                mode_opts_data,
                f"profile '{profile_id}' mode_opts",
            )
        elif mode == "adb_reverse":
            mode_opts = _from_dict(
                AdbReverseOpts, mode_opts_data, f"profile '{profile_id}' mode_opts"
            )
        else:
            raise ConfigValidationError(
                f"Unknown mode '{mode}' in profile '{profile_id}'"
            )

        # Parse rules
        rules_list = profile_dict.get("rules", [])
        if not isinstance(rules_list, list):
            raise ConfigValidationError(
                f"Profile '{profile_id}' 'rules' must be a list"
            )

        parsed_rules = []
        for i, rule_dict in enumerate(rules_list):
            rule = _from_dict(
                Rule, rule_dict, f"rule at index {i} of profile '{profile_id}'"
            )
            if rule in parsed_rules:
                raise ConfigValidationError(
                    f"Duplicate rule '{rule.name}' in profile '{profile_id}'"
                )
            if isinstance(rule.target, Tunnel):
                if rule.target.name not in mode_opts.tunnels:
                    raise ConfigValidationError(
                        f"Target tunnel '{rule.target.name}' in rule '{rule.name}' is not defined in mode_opts.tunnels"
                    )
                if rule.protocol != ["tcp"]:
                    raise ConfigValidationError(
                        f"Tunnel rule '{rule.name}' must match protocol tcp only"
                    )
            if parsed_rules and parsed_rules[-1].matches_all:
                raise ConfigValidationError(
                    f"Rule '{rule.name}' never matches, as '{parsed_rules[-1].name}' before it matches all traffic"
                )
            if (rule.app or rule.skuid) and mode == "wireguard_ssh_reverse":
                raise ConfigValidationError(
                    f"Rule '{rule.name}': app and skuid matching are not supported in wireguard_ssh_reverse mode. "
                    "Select the apps in the WireGuard app's tunnel settings instead."
                )
            if (
                (rule.sport or rule.dport)
                and not rule.protocol
                and mode == "adb_reverse"
            ):
                raise ConfigValidationError(
                    f"Rule '{rule.name}': sport and dport require a protocol in adb_reverse mode, "
                    "as iptables matches ports only with a protocol (-p)"
                )
            parsed_rules.append(rule)

        hooks = profile_dict.get("hooks", {})
        try:
            _validate_hooks(hooks)
        except ValueError as e:
            raise ConfigValidationError(f"Invalid hooks in profile '{profile_id}': {e}")

        # Instantiate profile
        parsed_profiles[profile_id] = Profile(
            mode=mode,
            rules=parsed_rules,
            mode_opts=mode_opts,
            hooks=hooks,
        )

    return Config(profiles=parsed_profiles)


def load_config(file_path: Path) -> Config:
    """Reads a configuration file and parses it into a Config object."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception as e:
        raise ConfigValidationError(f"Failed to read file {file_path}: {e}")
    logger.debug(f"Config {file_path}:\n{content}")
    return parse_config_string(content)
