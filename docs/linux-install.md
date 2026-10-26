# Linux installation

ChompEDR has one dependency script and one installer. The installer builds your
local checkout and installs the CLI, SSH/process/file collectors and read-only web
dashboard together. There is one installed executable, shared by the CLI and services.

## Install from a clone

On Ubuntu/Debian with internet access, run as your regular user from the repository:

```sh
bash scripts/install-dependencies-linux.sh
python3 scripts/install-linux.py
chompedr
```

The dependency script installs build tools, curl, CA certificates, Python 3 and
stable Rust if missing. The installer finds Cargo in your user installation even
if the current terminal has not picked up its PATH. Cargo downloads the locked
Rust dependencies while building. Compilation runs without root; the installer
then requests sudo to copy files, reload systemd, and enable/start the collectors
and dashboard. Python 3.9+ and a Linux host with systemd/journald are required.
Run the installer without sudo when building from source.

Open http://127.0.0.1:8765 inside the Linux machine/VM. For desktop access through
an SSH tunnel, see [dashboard access](dashboard.md).

Running `chompedr` prints the original gator banner and help, then exits.
Run commands in your normal terminal; there is no separate interactive prompt.
Commands with arguments, including JSON output, do not print the banner.

## Options

- `--replace`: upgrade an existing installation. The installer builds first,
  validates all destinations, stops installed collectors/dashboard, replaces
  files, reloads systemd and starts/enables services again.
- `--binary /path/to/chompedr`: skip compilation and install a native prebuilt
  Linux executable. Extracted snapshot packages are detected automatically.
- `--watch-path /absolute/path`: repeat to replace the default watched account
  files. Repeat custom paths on upgrade to preserve your selection.
- `--port 9000`: choose the dashboard's localhost port. Repeat on upgrade.
- `--no-start`: install files and reload systemd without enabling/starting
  services. During replacement, existing Chomp system services are stopped.
- `--destdir /absolute/stage --binary /path/to/chompedr`: stage files only;
  no build, root access, service changes or activation.

The installer puts the shared binary at `/usr/local/lib/chomp-edr/chompedr` and
a launcher at `/usr/local/bin/chompedr`. Standard Ubuntu PATH includes
`/usr/local/bin`. If your shell has cached an old path, run `hash -r` or open a
new terminal. When run as your regular user, a recognized old
`~/.local/bin/chompedr` copy is replaced with a launcher to the shared binary.
An old optional user SSH service is not removed automatically; disable it with
`systemctl --user disable --now chompedr.service` if you previously enabled it.

The former separate system/dashboard installers are retired. Existing system
installations can upgrade using the same installer:

```sh
git pull
python3 scripts/install-linux.py --replace
chompedr
```

Each file is replaced atomically; the full installation is not transactional.
If a write fails, correct the error and rerun with `--replace`.
SSH checkpoints are preserved, but rule changes can require the
[recovery procedure](ssh-demo.md#restart-recovery-journal-json-only).
Process/file collectors establish new baselines on restart.

## Verify and control

```sh
chompedr --version
chompedr list-rules
systemctl status chompedr-ssh chompedr-processes chompedr-files chompedr-dashboard
sudo journalctl -u chompedr-dashboard -n 30 --no-pager
```

See [system services](system-service.md) for collector behavior and
[the dashboard guide](dashboard.md) for browser access and diagnostics.
