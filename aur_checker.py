#!/usr/bin/env python3
import subprocess
import re
import sys
import json
import argparse
import logging
from typing import List, Tuple, Optional, Dict, Any
from packaging.version import Version, InvalidVersion
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

LOGGER = logging.getLogger("aur_checker")


def configure_logging(level: str) -> None:
    """
    Configure root logger with a simple handler, allowing reconfiguration.
    """
    if LOGGER.hasHandlers():
        LOGGER.handlers.clear()
    numeric_level = getattr(logging, level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"Invalid log level: {level}")
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        '%(asctime)s %(levelname)-8s %(message)s',
        '%Y-%m-%d %H:%M:%S'
    )
    handler.setFormatter(formatter)
    LOGGER.setLevel(numeric_level)
    LOGGER.addHandler(handler)


def fetch_raw_updates(commands: List[str]) -> str:
    """
    Try each command in order until one returns output; raise if none succeed.
    """
    last_err: Optional[Exception] = None
    for cmd in commands:
        try:
            LOGGER.debug(f"Running update command: {cmd}")
            return subprocess.check_output(cmd.split(), text=True)
        except FileNotFoundError as e:
            LOGGER.warning(f"Command not found: {cmd}")
            last_err = e
        except subprocess.CalledProcessError as e:
            LOGGER.warning(f"Command {cmd} failed: {e}")
            last_err = e
    LOGGER.error("No update command succeeded; unable to fetch updates.")
    raise last_err


def parse_updates(output: str, verbose: bool) -> List[Tuple[str, Version, Version]]:
    """
    Parse lines of `pkg old -> new` into Version pairs.
    """
    updates: List[Tuple[str, Version, Version]] = []
    pattern = re.compile(r'^(?P<pkg>\S+)\s+(?P<old>\S+)\s+->\s+(?P<new>\S+)$')
    skipped = 0

    for line in output.splitlines():
        match = pattern.match(line)
        if not match:
            skipped += 1
            LOGGER.debug(f"Skipping unparsable line: {line}")
            continue
        old_str, new_str = match.group('old'), match.group('new')
        try:
            old_v = Version(old_str)
            new_v = Version(new_str)
        except InvalidVersion:
            skipped += 1
            LOGGER.debug(f"Invalid version strings: {old_str}, {new_str}")
            continue
        updates.append((match.group('pkg'), old_v, new_v))

    if verbose and skipped:
        LOGGER.warning(f"Skipped {skipped} unparsable or invalid lines.")
    return updates


def semantic_diff(old: Version, new: Version) -> Tuple[str, str]:
    """
    Compute release difference and semantic category.
    """
    old_parts = list(old.release) + [0, 0, 0]
    new_parts = list(new.release) + [0, 0, 0]
    deltas = [n - o for o, n in zip(old_parts, new_parts)]
    if deltas[0] > 0:
        label = 'major'
    elif deltas[1] > 0:
        label = 'minor'
    elif deltas[2] > 0:
        label = 'patch'
    elif new.is_prerelease or old.is_prerelease:
        label = 'prerelease'
    else:
        label = 'none'
    diff_str = '.'.join(str(abs(d)) for d in deltas[:3])
    return diff_str, label


def format_human(updates: List[Dict[str, Any]]) -> None:
    """
    Print a colorized table with extra spacing for readability.
    """
    pkg_w = max(len(u['pkg']) for u in updates) + 4
    old_w = max(len(u['old']) for u in updates) + 4
    new_w = max(len(u['new']) for u in updates) + 4
    diff_w = max(len(u['diff']) for u in updates) + 4

    header = (f"{'Package':{pkg_w}}{'Old Version':{old_w}}"
              f"{'New Version':{new_w}}{'Diff':{diff_w}} Type")
    sep = '-' * len(header)
    print(Style.BRIGHT + header)
    print(sep)

    colors = {
        'major': Fore.LIGHTRED_EX,
        'minor': Fore.LIGHTYELLOW_EX,
        'patch': Fore.LIGHTGREEN_EX,
        'prerelease': Fore.LIGHTMAGENTA_EX,
        'none': Fore.LIGHTBLACK_EX,
    }

    for u in updates:
        color = colors.get(u['type'], Fore.WHITE)
        print(
            f"{Fore.CYAN}{u['pkg']:{pkg_w}}"
            f"{Fore.RED}{u['old']:{old_w}}"
            f"{Fore.GREEN}{u['new']:{new_w}}"
            f"{color}{u['diff']:{diff_w}}"
            f"{color}{u['type']}"
        )


def run_checker(
    commands: List[str],
    include_zero: bool,
    verbose: bool
) -> List[Dict[str, Any]]:
    """
    Core logic: fetch, parse, diff, filter, and structure.
    """
    raw = fetch_raw_updates(commands)
    parsed = parse_updates(raw, verbose)

    results: List[Dict[str, Any]] = []
    for pkg, old_v, new_v in parsed:
        diff_str, label = semantic_diff(old_v, new_v)
        if not include_zero and diff_str == '0.0.0' and label == 'none':
            continue
        results.append({
            'pkg': pkg,
            'old': str(old_v),
            'new': str(new_v),
            'diff': diff_str,
            'type': label
        })
    return results


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Enhanced AUR update checker with semantic diffs"
    )
    parser.add_argument(
        '-c', '--cmds', nargs='+',
        default=['paru -Qu', 'yay -Qu', 'pacman -Qu'],
        help="Commands to try for fetching AUR updates"
    )
    parser.add_argument(
        '-f', '--format', choices=['text', 'json'],
        default='text', help="Output format"
    )
    parser.add_argument(
        '-z', '--include-zero-diff', action='store_true',
        help="Include updates with no net version change"
    )
    parser.add_argument(
        '--log-level', default='INFO',
        help="Logging level (DEBUG, INFO, WARNING, ERROR)"
    )
    parser.add_argument(
        '-v', '--verbose', action='store_true',
        help="Show parsing warnings"
    )
    args = parser.parse_args()

    try:
        configure_logging(args.log_level)
        processed = run_checker(args.cmds, args.include_zero_diff, args.verbose)
    except Exception as e:
        LOGGER.error(f"Failed to fetch updates: {e}")
        sys.exit(1)

    # Handle no updates
    if not processed:
        if args.format == 'json':
            print(json.dumps([], indent=2))
        else:
            print(Fore.YELLOW + "No updates found or all diffs zero.")
        sys.exit(0)

    # Output results
    if args.format == 'json':
        print(json.dumps(processed, indent=2))
    else:
        format_human(processed)

                # Prompt user to update packages using the best available tool
        try:
            choice = input("Do you want to update now? (y/n): ").strip().lower()
        except KeyboardInterrupt:
            print("\nUpdate canceled by user.")
            sys.exit(0)

        if choice == 'y':
            LOGGER.info("Starting system update using the best helper...")
            # Try AUR helpers first, then fall back to pacman
            update_cmds = [
                ["paru", "-Syu"],
                ["yay", "-Syu"],
                ["sudo", "pacman", "-Syu"]
            ]
            try:
                for cmd in update_cmds:
                    try:
                        subprocess.run(cmd, check=True)
                        break
                    except FileNotFoundError:
                        LOGGER.warning(f"Update tool not found: {cmd[0]}")
                    except subprocess.CalledProcessError as e:
                        LOGGER.error(f"Update failed with {cmd[0]}: {e}")
                        sys.exit(1)
            except KeyboardInterrupt:
                LOGGER.error("Update interrupted by user.")
                sys.exit(1)
        else:
            LOGGER.info("Update skipped by user.")

if __name__ == '__main__':
    main()
