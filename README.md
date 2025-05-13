# aur-update-checker

A lightweight command‑line tool to check AUR package updates with semantic version diffs.

## Features

* **Modular design**: Separate functions for fetching, parsing, diffing, and formatting.
* **Multiple fetch commands**: Tries `paru`, `yay`, then `pacman` for updates.
* **Semantic diffs**: Classifies changes as `major`, `minor`, `patch`, or `prerelease`.
* **Colorized output**: Human‑friendly table with ANSI color coding.
* **JSON output**: Machine‑readable mode for scripting and automation.
* **Verbose logging**: Detailed warnings when parsing irregular lines.

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/OTAKUWeBer/aur-update-checker.git
   cd aur-update-checker
   ```
2. (Optional) Create a virtual environment:

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```
3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   # On Arch Linux, these are typically provided by the core python-packaging and python-colorama packages
   ```

## Usage

Run the script directly:

```bash
./aur_checker.py [options]
```

### Options

* `-c, --cmds CMD1 CMD2 ...`
  Commands to try for fetching updates (default: `paru -Qu`, `yay -Qu`, `pacman -Qu`).

* `-f, --format {text,json}`
  Output format (default: `text`).

* `-z, --include-zero-diff`
  Include packages with no semantic version change.

* `-v, --verbose`
  Show parsing warnings for skipped lines.

* `--log-level LEVEL`
  Logging level: `DEBUG`, `INFO`, `WARNING`, `ERROR` (default: `INFO`).

### Examples

* Show only non-zero diffs in colorized table:

  ```bash
  ./aur_checker.py
  ```

* Output JSON for automation:

  ```bash
  ./aur_checker.py -f json > updates.json
  ```

* Include zero-diff entries and debug logs:

  ```bash
  ./aur_checker.py -z -v --log-level DEBUG
  ```

## Contributing

1. Fork the repo
2. Create a feature branch
3. Commit your changes
4. Open a pull request

Please follow the existing code style and include unit tests for any new functionality.