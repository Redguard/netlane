import argparse
import io
import logging
import os
import sys
from pathlib import Path
from typing import Dict

from netlane.config import Config, ConfigValidationError, load_config
from netlane.modes import adb_reverse, wireguard_ssh_reverse
from netlane.modes.interface import Mode, StepError
from netlane.utils import COLOR_CHOICES, config_dir, setup_logging

logger = logging.getLogger(__name__)

MODES: Dict[str, Mode] = {
    "wireguard_ssh_reverse": wireguard_ssh_reverse,
    "adb_reverse": adb_reverse,
}


def mode_steps(mode: Mode) -> str:
    """The steps to run in order. down is left out as it only cleans up."""
    return " → ".join(step for step in mode.STEPS if step != "down")


def modes_overview() -> str:
    name_width = max(len(name) for name in MODES)
    summary_width = max(len(mode.SUMMARY) for mode in MODES.values())
    lines = ["modes:"]
    for name, mode in MODES.items():
        lines.append(
            f"  {name:<{name_width}}  {mode.SUMMARY:<{summary_width}}  {mode_steps(mode)}"
        )
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Mobile WG Interception Setup",
        epilog=modes_overview(),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show debug output like executed commands",
    )
    parser.add_argument(
        "--config",
        default=config_dir() / "config.toml",
        type=Path,
        help="Path to the TOML config file (default: %(default)s)",
    )
    parser.add_argument(
        "--color",
        choices=COLOR_CHOICES,
        default="auto",
        help="Color the output (default: %(default)s)",
    )
    parser.add_argument(
        "--log",
        type=Path,
        metavar="PATH",
        help="Also write a JSON Lines log including debug output to PATH",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    setup_parser = subparsers.add_parser(
        "setup",
        help="One-time setup of a dedicated remote server",
        description="One-time setup of the profile's remote server. Assumes the server is used for nothing else.",
    )
    setup_parser.add_argument("profile", help="Name of the profile")
    setup_parser.add_argument(
        "--distro",
        required=True,
        choices=list(wireguard_ssh_reverse.DISTRO_SCRIPTS.keys()),
        help="Linux distribution to install on",
    )

    pair_parser = subparsers.add_parser(
        "pair",
        help="Create keys and show the client config as a QR code",
        description="Create keys and show the client config as a QR code. Requires setup first.",
    )
    pair_parser.add_argument("profile", help="Name of the profile")
    pair_parser.add_argument(
        "--save",
        type=Path,
        metavar="PATH",
        help="Also save the client config to PATH",
    )
    pair_parser.add_argument(
        "--force",
        action="store_true",
        help="Replace existing keys",
    )

    up_parser = subparsers.add_parser(
        "up",
        help="Apply the profile and start its tunnels until Ctrl-C",
        description="Apply the profile and start its tunnels until Ctrl-C. Requires setup and pair first if the profile's mode has them.",
    )
    up_parser.add_argument("profile", help="Name of the profile")

    down_parser = subparsers.add_parser("down", help="Clean up after an interrupted up")
    down_parser.add_argument("profile", help="Name of the profile")

    subparsers.add_parser("list", help="List profiles with their mode and steps")

    return parser


def list_profiles(config: Config) -> None:
    if not config.profiles:
        return
    name_width = max(len(name) for name in config.profiles)
    mode_width = max(len(profile.mode) for profile in config.profiles.values())
    for name, profile in config.profiles.items():
        steps = mode_steps(MODES[profile.mode])
        print(f"{name:<{name_width}}  {profile.mode:<{mode_width}}  {steps}")


def run_step(args: argparse.Namespace, config: Config) -> None:
    name = args.profile
    profile = config.profiles.get(name)
    if profile is None:
        raise StepError(f"Profile '{name}' not found in {args.config}")

    step = args.command
    mode = MODES[profile.mode]
    if step not in mode.STEPS:
        raise StepError(f"Profile '{name}' ({profile.mode}) has no {step} step.")

    if step == "setup":
        mode.setup(name, profile, args.distro)
    elif step == "pair":
        mode.pair(name, profile, args.save, args.force)
    elif step == "up":
        mode.up(name, profile)
    elif step == "down":
        mode.down(name, profile)

    later_steps = mode.STEPS[mode.STEPS.index(step) + 1 :]
    if later_steps and later_steps[0] != "down":
        logger.info(f"Next: {later_steps[0]} {name}")


def main():
    # Piped output otherwise uses the locale's encoding, e.g. cp1252 on Windows.
    for stream in (sys.stdout, sys.stderr):
        if isinstance(stream, io.TextIOWrapper):
            stream.reconfigure(encoding="utf-8")
    if sys.platform == "win32":
        os.system("")  # Enables escape codes in the console as a side effect.

    args = build_parser().parse_args()
    context = {"step": args.command}
    if "profile" in args:
        context["profile"] = args.profile
    setup_logging(args.verbose, args.color, args.log, context)
    logger.debug(f"Arguments: {vars(args)}")

    try:
        config = load_config(args.config)
    except ConfigValidationError as e:
        logger.error(f"Failed to load config: {e}")
        sys.exit(1)

    try:
        if args.command == "list":
            list_profiles(config)
        else:
            run_step(args, config)
    except StepError as e:
        logger.error(str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()
