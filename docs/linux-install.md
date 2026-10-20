# Linux installation and optional user service

For boot startup, logout-independent monitoring, and automatic restarts of SSH, process and file collectors, use the [always-on system installation](system-service.md). The user-service instructions below cover SSH only and retain manual restart behavior.

Requirements: Linux, Python 3 for installation, and a locally built `chompedr` binary. Live monitoring also requires systemd/journalctl and an account with access to the SSH journal. This installer does not grant access, install dependencies, edit shell startup files, or change system services.

## Install from the repository

Build on the Linux machine where you will run Chomp:

```sh
cargo build --release --locked
python3 scripts/install-linux.py
export PATH="$HOME/.local/bin:$PATH"
chompedr --version
chompedr monitor --once
```

The executable is installed at `$HOME/.local/bin/chompedr`. The PATH command applies to the current shell; add that directory to your preferred shell configuration separately if desired. `--prefix /absolute/path` changes the installation prefix. `--binary /path/to/chompedr` selects another trusted local build. Do not use sudo: this is a user-account installation, not a system-wide installation.

`monitor --once` includes the last 60 seconds on its first run. Inspect journalctl diagnostics and verify that the account can read SSH authentication records; a successful quiet scan does not establish complete journal access. Foreground monitoring is started with `chompedr monitor` and stopped with Ctrl+C.

## Optional background service

To install the binary and write a user service in one step:

```sh
python3 scripts/install-linux.py --service
```

If the binary is already installed, stop any active monitor and add `--replace`. The service file is written to `$XDG_CONFIG_HOME/systemd/user/chompedr.service` or `$HOME/.config/systemd/user/chompedr.service`. It records absolute binary and checkpoint paths; the checkpoint path uses the installer's `$XDG_STATE_HOME/chomp-edr/ssh` or `$HOME/.local/state/chomp-edr/ssh`. Spaces are supported. Service executable/checkpoint paths containing backslash, quote, dollar, or percent characters are rejected before installation to avoid systemd expansion ambiguity.

The installer leaves the service disabled and stopped. After reviewing the generated file and checking journal access, explicitly run:

```sh
systemctl --user daemon-reload
systemctl --user start chompedr.service
systemctl --user status chompedr.service
journalctl --user -u chompedr.service -f -o cat
```

The journal view includes JSON alerts and diagnostics. `chompedr monitor --status` inspects checkpoint state; it is not a replacement for the service status command. Pass the recorded `--checkpoint` directory if your current shell's state-directory environment differs from installation time. Do not run a foreground monitor against the same checkpoint while the service owns it.

For optional startup with your user manager:

```sh
systemctl --user enable chompedr.service
```

User-manager lifetime depends on login/session configuration. This does not promise unattended boot monitoring, and the installer does not enable lingering. The unit uses `Restart=no`: errors remain visible until you investigate and restart it. Stopping the unit terminates its entire process group, including journalctl. The service uses a private file-creation mask and does not gain extra privileges.

## Upgrade and removal

Stop the service (or foreground process), build the new version, then replace the installed files:

```sh
systemctl --user stop chompedr.service
cargo build --release --locked
python3 scripts/install-linux.py --service --replace
systemctl --user daemon-reload
systemctl --user start chompedr.service
```

`--replace` replaces the generated unit as well as the binary when `--service` is selected; preserve any manual unit edits first. Each file is replaced atomically, but the pair is not a filesystem transaction. An interrupted installation can be completed by rerunning with `--replace`. Checkpoint data is never deleted or migrated. If built-in rules changed, checkpoint compatibility checks can prevent startup; review the recovery guide before explicitly choosing a new checkpoint directory.

To remove a default installation:

```sh
systemctl --user disable --now chompedr.service
rm -- "${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/chompedr.service"
systemctl --user daemon-reload
rm -- "$HOME/.local/bin/chompedr"
```

Skip service commands if you never installed one. Substitute the actual installed paths for custom locations. Keep checkpoint data unless you deliberately want to discard the detection window and retry state.

## Validation scope

CI installs into disposable user directories, checks the copied binary, validates the generated unit with `systemd-analyze verify`, checks explicit upgrades, and verifies that no service-control command runs. Unit validation does not start a user service. The separate real-SSH test verifies the monitor/collector lifecycle on Ubuntu. Running the service under the target machine's user manager and validating its journal permissions remain deployment checks.

References: [systemd service command syntax](https://www.freedesktop.org/software/systemd/man/systemd.service.html), [unit validation](https://www.freedesktop.org/software/systemd/man/systemd-analyze.html). See also [monitoring and recovery](ssh-demo.md).
