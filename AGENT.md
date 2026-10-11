# AGENT.md - Developer & Agent Guide for netlane

This document provides architectural context, development guidelines, and testing workflows for AI coding agents and human developers working on `netlane`.

---

## 1. Project Overview

`netlane` is a command-line tool designed to simplify mobile application network interception during security assessments and penetration tests.

### Core Problem It Solves
Traditional mobile network interception often involves error-prone, fragile, manual setups: configuring custom VPN profiles, configuring local or remote firewalls, managing reverse tunnels, and handling dual-stack IPv4/IPv6 traffic. `netlane` automates this with declarative configuration profiles in TOML, selectively routing traffic of targeted applications (or specific IP/ports/protocols) through proxy listeners (such as Burp Suite or mitmproxy) while allowing other traffic to pass directly to the internet or dropping/rejecting unwanted connections (e.g. QUIC/UDP 443).

### Key Concepts
- **Profile**: A named configuration entry defining a mode, mode-specific options (`mode_opts`), interception rules (`rules`), and optional lifecycle hooks (`hooks`).
- **Rule**: An ordered interception rule evaluated top-to-bottom. The first matching rule wins. Packets matching no rule are dropped by default.
- **Target**: An action (`action:passthrough`, `action:reject`, `action:drop`) or a reverse tunnel (`tunnel:<name>`).
- **Tunnel**: A named reverse TCP tunnel forwarding traffic from the mobile device/gateway to a local analyst port (e.g. `main = 8080`).

---

## 2. Operational Modes & Architecture

`netlane` supports two distinct interception modes:

### Mode 1: `wireguard_ssh_reverse` (Remote VPS Gateway)
Designed for any mobile device (iOS, non-rooted Android, etc.) connecting via the WireGuard client app to a dedicated Linux VPS (e.g., Ubuntu).

```
Mobile App -> WireGuard (Mobile) ==[UDP 51820]==> WireGuard Server (VPS)
                                                         |
                   +-------------------------------------+-----------------------------------+
                   | (Match: tunnel:<name>)              | (Match: passthrough)              | (Match: reject/drop)
                   v                                     v                                   v
             nftables DNAT                         nftables MASQUERADE                   nftables drop/reject
                   v                                     v                                   v
             sshd (VPS)                             Internet                             Blocked
                   v (SSH Reverse Tunnel)
            Burp / MitM (Host)
```

- **Requirements**: Local `ssh`, `scp`, `wg` (WireGuard tools). Remote dedicated Ubuntu VPS with root access (`sudo`, `doas`, `su`, or direct root). WireGuard app on test device.
- **Ruleset Backend**: `nftables` via `src/netlane/rulesets/nftables.py`. Generates an atomic `nft` script for table `inet netlane` with `prerouting`, `input`, `forward`, and `postrouting` chains.
- **Dual-Stack**: Full IPv4 (`10.10.10.0/24`) and IPv6 (`fd10:10:10::/64`) support inside the tunnel.
- **Lifecycle Steps**:
  1. `setup`: One-time preparation of the dedicated VPS using `src/netlane/scripts/ubuntu/install.sh`. Configures base firewall policies and dependencies (`wireguard`, `conntrack`).
  2. `pair`: Generates server and client WireGuard keypairs, deploys server configuration to `/etc/wireguard/wg0.conf`, and displays the client configuration as an ASCII QR code (or exports to disk with `--save`).
  3. `up`: Starts the WireGuard interface, flushes conntrack, applies the `nftables` ruleset, registers `wg0` into trusted interfaces, and establishes SSH reverse tunnels (`ssh -N -R ...`). Blocks until Ctrl-C.
  4. `down`: Teardown hook, stops WireGuard interface, deletes `nftables` table, flushes conntrack.
- **Special Considerations**:
  - `app` and `skuid` matching are **not supported** in this mode (traffic arrives at the VPS with app identity stripped). App selection is done in the WireGuard client app settings on the device.
  - Client configuration defaults to `DNS = 1.1.1.1`; rules must allow DNS traffic through.

### Mode 2: `adb_reverse` (Rooted Device / Emulator)
Designed for rooted Android devices or emulators using `iptables` and `adb reverse`.

```
Mobile App -> OS Network Stack (Android)
                    |
      +-------------+-------------+-----------------------+
      | (Match: tunnel:<name>)     | (Match: passthrough)  | (Match: reject/drop)
      v                           v                       v
iptables nat DNAT to 127.0.0.1   iptables filter RETURN   iptables filter DROP/REJECT
      v                           v                       v
 adbd (localhost:port)         Internet                 Blocked
      v (adb reverse)
Burp / MitM (Host)
```

- **Requirements**: Local `adb`, rooted Android device or emulator with root shell (`su` for Magisk/KernelSU or root adbd).
- **Ruleset Backend**: `iptables` / `ip6tables` via `src/netlane/rulesets/iptables.py`. Injects custom chains (`netlane` in `nat` and `filter`, `netlane_input` in `filter`) using `iptables-restore` heredocs.
- **App & UID Matching**: Resolves Android package names to UIDs across all user profiles (calling `pm list users` and `cmd package list packages -U --user <uid>`), applying `-m owner --uid-owner <uid>`.
- **Reverse Tunnels**: Configured via `adb reverse tcp:<port> tcp:<port>`.
- **Lifecycle Steps**:
  1. `up`: Verifies root shell and port availability, checks for IPv6 NAT support, resolves package UIDs, applies iptables script, establishes `adb reverse` tunnels, and monitors connection status via background `adb wait-for-disconnect`. Blocks until Ctrl-C or device disconnects.
  2. `down`: Removes reverse tunnels, removes `iptables` chains and hooks.
- **Special Considerations**:
  - Traffic to loopback and device's own addresses bypasses rules.
  - `adbd` listening ports are dynamically discovered and exempt from rules so ADB over network/Wi-Fi does not disconnect.
  - Connections established prior to `up` that match tunnel rules are reset with TCP RST to force apps to reconnect through the proxy.
  - If device kernel lacks IPv6 NAT, tunnel rules matching IPv6 will error unless explicitly restricted to IPv4 with `daddr = ["0.0.0.0/0"]`.

---

## 3. Repository Structure

```
netlane/
├── config.toml                     # Example / default configuration file
├── pyproject.toml                  # Project metadata, dependencies, entry points, tool configurations
├── README.md                       # User documentation and architectural diagrams
├── src/
│   └── netlane/
│       ├── __init__.py             # Defines APP_NAME ("netlane")
│       ├── __main__.py             # Executable module entry point
│       ├── cli.py                  # CLI definition, argument parsing, command dispatch
│       ├── config.py               # TOML parser, validation schemas, dataclasses
│       ├── adb.py                  # ADB process execution, shell runners, temp file management
│       ├── remote.py               # Remote SSH/SCP execution and elevation wrappers
│       ├── utils.py                # Command execution (run_cmd), logging, paths, signal handling
│       ├── modes/
│       │   ├── __init__.py
│       │   ├── interface.py        # Mode Protocol and StepError definition
│       │   ├── adb_reverse.py      # Implementation of adb_reverse mode
│       │   └── wireguard_ssh_reverse.py # Implementation of wireguard_ssh_reverse mode
│       ├── rulesets/
│       │   ├── __init__.py
│       │   ├── iptables.py         # iptables / ip6tables script generation & teardown
│       │   └── nftables.py         # nftables script generation & teardown
│       └── scripts/
│           └── ubuntu/
│               └── install.sh      # VPS bootstrapping script for wireguard_ssh_reverse
└── tests/
    ├── conftest.py
    ├── resources/                  # TOML test fixtures (full_example.toml, etc.)
    ├── test_adb.py                 # Tests for adb helper wrappers
    ├── test_adb_reverse.py         # Unit & mock step tests for adb_reverse mode
    ├── test_cli.py                 # Argument parsing and CLI dispatch tests
    ├── test_config_parser.py       # Comprehensive TOML parsing and validation tests
    ├── test_iptables.py            # iptables generation and formatting tests
    ├── test_nftables.py            # nftables generation and formatting tests
    ├── test_remote.py              # SSH / SCP remote command execution tests
    ├── test_utils.py               # Utility, logging, and signal handling tests
    └── test_wireguard_ssh_reverse.py # Unit & mock step tests for wireguard_ssh_reverse mode
```

---

## 4. Development Workflow & Commands

Development and packaging use [uv](https://docs.astral.sh/uv/).

### Setup
```bash
uv sync
```

### Running Tests
Run the entire test suite:
```bash
uv run pytest
```
Run a specific test module:
```bash
uv run pytest tests/test_config_parser.py
```
Run tests matching a specific expression:
```bash
uv run pytest -k "test_up"
```

### Type Checking
Type checking is configured with `pyright` in standard mode (target Python 3.12, includes `src` and `tests`):
```bash
uv run pyright
```

### Code Formatting
Formatting is enforced using `black` targeting Python 3.12:
```bash
# Check formatting
uv run black --check .

# Auto-format
uv run black .
```

### Running the CLI Locally
```bash
# Show help and available modes
uv run netlane --help

# List profiles from a specific config
uv run netlane --config config.toml list

# Verbose output with command traces
uv run netlane -v --config config.toml up rooted
```

---

## 5. Working on TOML Configs & Parser (`config.py`)

### Config Schema Overview
Configurations are structured as:
- Root table: `[profiles.<profile_name>]`
- Each profile requires:
  - `mode`: `"wireguard_ssh_reverse"` or `"adb_reverse"`
  - `mode_opts`: Mode-specific configuration dictionary
  - `rules`: List of rule tables (evaluated top-to-bottom)
  - `hooks`: Optional map of lifecycle hooks (`pre_up`, `post_up`, `pre_down`, `post_down`)

### Strict Validation Invariants
The parser in `src/netlane/config.py` enforces strict validation rules:
1. **Unknown Keys**: Any unknown keys at root, profile, `mode_opts`, or rule level raise `ConfigValidationError`.
2. **Rule Fields**:
   - `name`: Must match `^[A-Za-z0-9 _.,:()/+-]{1,128}$`.
   - `target`: Must be `action:passthrough`, `action:reject`, `action:drop`, or `tunnel:<name>`.
   - Match criteria (`saddr`, `daddr`, `protocol`, `sport`, `dport`, `skuid`, `app`) **must be lists** if specified, and cannot be empty lists.
   - Address families across `saddr` and `daddr` within a single rule must match.
   - Port numbers: `1 <= port <= 65535`.
   - UID numbers: `0 <= uid <= 2^32 - 2`.
3. **Tunnel Target Rules**:
   - The named tunnel must exist in `mode_opts.tunnels`.
   - Protocol **must be `["tcp"]` only** (reverse tunnels only handle TCP streams).
4. **Unreachable Rules**:
   - A rule placed after a rule that matches all traffic (`matches_all == True`) is rejected during parsing.
5. **Mode-Specific Restrictions**:
   - `app` and `skuid` are forbidden in `wireguard_ssh_reverse`.
   - `sport` and `dport` require `protocol` in `adb_reverse` because iptables requires `-p` for port matching.
6. **Host & Usernames**:
   - `ssh_host`: Valid RFC 1123 hostname or IP address without zone index.
   - `ssh_user`: Lowercase alphanumeric / underscore (`^[a-z_][a-z0-9_-]{0,31}$`).
   - `elevation`: One of `""`, `"sudo"`, `"doas"`, `"su"`.

### Modifying or Adding Config Fields
When adding or altering configuration fields:
1. Update the appropriate dataclass (`Profile`, `Rule`, `WireguardSSHReverseOpts`, `AdbReverseOpts`) in `src/netlane/config.py`.
2. Add validation functions or checks in `__post_init__` or `parse_config_string`.
3. Add tests to `tests/test_config_parser.py`:
   - Happy path with valid values.
   - Rejection of invalid types/values.
   - Strict rejection of unknown keys.
4. Update `config.toml`, `tests/resources/full_example.toml`, and the documentation in `README.md`.

---

## 6. Working on Modes & Rulesets

### The `Mode` Protocol (`src/netlane/modes/interface.py`)
Each mode implements the `Mode` protocol:
- `SUMMARY: str`: One-line description shown in `netlane --help` and `list`.
- `STEPS: Tuple[str, ...]`: Allowed steps in execution order (e.g. `("setup", "pair", "up", "down")` or `("up", "down")`).
- `setup(name, profile, distro)`: Server bootstrapping (if applicable).
- `pair(name, profile, save_path, force)`: Key generation and provisioning (if applicable).
- `up(name, profile)`: Applies firewall rules, opens tunnels, and blocks until interrupted.
- `down(name, profile)`: Cleans up rules, tunnels, and restores previous network state.

### Ruleset Generation Principles
- **Deterministic Output**: Rulesets generated by `nftables.py` and `iptables.py` must strictly follow the ordering defined in the profile.
- **Atomic Operations**:
  - nftables uses a single transaction script loaded with `nft -f` and tears down cleanly via `destroy table inet netlane`.
  - iptables uses `iptables-restore -w -n` heredocs to prevent transient packet leaks, and scoped custom chains (`netlane`, `netlane_input`) for easy flushing.
- **Teardown Idempotence**: `down` must always succeed without errors even if `up` failed midway or was never executed.
- **Connection Tracking Safety**:
  - Existing connections in `conntrack` must be flushed on `up` and `down` to prevent traffic bypassing rules through pre-established connections.
- **Signal Handling & Clean Shutdown**:
  - The `up` routine catches `KeyboardInterrupt` and invokes `down`.
  - Accidental double-taps of Ctrl-C within 2 seconds during teardown are caught by `teardown_sigint_handler()` to protect against half-torn-down firewall states.

---

## 7. Writing & Maintaining Tests

The test suite uses `pytest` and runs in under 1 second without requiring physical Android devices, emulators, or remote VPS servers.

### Testing Conventions & Patterns
1. **Mocking Remote and Local Commands**:
   - Use `monkeypatch` to intercept low-level runners (`remote.run`, `remote.run_script`, `adb.run`, `adb.shell`, `adb.run_script`, `subprocess.run`, `shutil.which`).
   - Use test fixtures to simulate state:
     - `server` fixture in `tests/test_wireguard_ssh_reverse.py` simulates server setup state, pairing state, and interface status.
     - `device` fixture in `tests/test_adb_reverse.py` simulates ADB device connection, root privileges, active tunnels, user listings, and package UID queries.
2. **Testing Ruleset Compilers**:
   - Test rule generation against exact expected output scripts in `tests/test_nftables.py` and `tests/test_iptables.py`.
   - Verify handling of single and multiple ports, protocols, IP subnets, mixed IPv4/IPv6, and UID mappings.
3. **Testing Parser Validation**:
   - Use `pytest.mark.parametrize` with expressive `id="..."` tags in `tests/test_config_parser.py`.
   - Test both positive cases (`parse_config_string`) and expected exceptions (`pytest.raises(ConfigValidationError, match=...)`).
4. **Testing CLI Behavior**:
   - Test argument parsing, flag overrides (`--config`, `--log`, `--color`, `-v`), and subcommand execution in `tests/test_cli.py`.

---

## 8. Updating Documentation

Whenever modifying CLI options, rules, config options, or mode behaviors:
1. **`README.md`**:
   - Update architecture diagrams (Mermaid flowcharts / sequence diagrams) if data flow changes.
   - Update the Configuration table (keys, descriptions, rule match fields).
   - Update the Usage section if commands, subcommands, or flags are added or changed.
   - Keep platform configuration paths up to date.
2. **`config.toml`**:
   - Ensure the example configuration file in the repository root demonstrates standard usage and best practices.
3. **CLI Help Strings**:
   - Ensure `build_parser()` in `src/netlane/cli.py` and mode `SUMMARY` strings accurately describe behavior.

---

## 9. Error Handling & Coding Guidelines

- **User-Facing Errors**: Use `StepError` (for runtime step failures) and `ConfigValidationError` (for configuration errors). Always provide actionable guidance in the error message (e.g. `"Run 'setup jailed' first"` or `"Restrict them to IPv4 with daddr = ['0.0.0.0/0']"`).
- **Subprocess Execution**:
  - Use `run_cmd` in `src/netlane/utils.py`.
  - Pass `secret=True` when running commands that output sensitive key material (e.g. `wg genkey`) to prevent leakage into debug logs.
- **Logging**:
  - Use `logger.debug` for raw shell commands, executed scripts, and internal data dumps.
  - Use `logger.info` for high-level progress (e.g. `"Starting WireGuard interface..."`, `"Local tunnel endpoints: 127.0.0.1:8080"`).
  - Use `logger.warning` / `logger.error` for issues requiring user intervention.
- **Code Style**:
  - Preserve Python 3.12+ idioms (e.g., structural pattern matching `match / case`, `dataclasses`, `pathlib.Path`, `tomllib`).
  - Keep functions focused and well-commented where network semantics are non-obvious (e.g., conntrack flushing, `adbd` listen socket detection via `/proc/net/tcp`).
