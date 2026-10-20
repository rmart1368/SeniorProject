# Downloadable development builds

Successful CI jobs produce native packages for Windows, Linux, and macOS. These are unsigned development snapshots, not tagged releases. Choose a package with the OS and CPU architecture of the machine where you intend to run it; one operating system's executable cannot be used on another.

## Download

1. Open the repository's [Rust checks runs](https://github.com/rmart1368/SeniorProject/actions/workflows/ci.yml).
2. Choose a successful run for the intended branch and commit. Current development is on `feature/ssh-detection`.
3. Under **Artifacts**, download the `chomp-edr` artifact matching your OS and architecture. GitHub may require sign-in.
4. Extract the GitHub artifact ZIP. Inside are the native package (`.zip` on Windows or `.tar.gz` on Linux/macOS) and its `.sha256` checksum file.
5. Verify the archive checksum, then extract that native package. Read `START-HERE.txt` in the resulting folder.

Artifacts are retained for 14 days. A later run can produce a new build after older artifacts expire. Upload happens only after that platform's tests, release build, and extracted-package smoke test pass. Prefer a run where the entire platform matrix succeeded.

## Verify the download

In PowerShell, calculate the hash of the inner Windows archive:

```powershell
Get-FileHash .\chomp-edr-<version>-windows-<architecture>-<commit>.zip -Algorithm SHA256
```

Compare it with the value in the adjacent `.sha256` file. On Linux, from the folder containing the inner archive and checksum:

```sh
sha256sum -c chomp-edr-<version>-linux-<architecture>-<commit>.tar.gz.sha256
```

On macOS use `shasum -a 256 -c` with the macOS checksum filename. Replace placeholders with the actual downloaded filename. Checksums detect corruption; they do not replace publisher signing. These builds are not Windows code-signed or macOS-notarized.

## Run without Rust

Open a terminal inside the fully extracted native package. On Windows:

```powershell
.\chompedr.exe
```

On Linux/macOS:

```sh
./chompedr
```

Running without arguments prints help and exits. To try the supplied synthetic SSH demo on Linux/macOS:

```sh
./chompedr scan -r rules/ssh.yaml -i examples/ssh-demo.log --input-format ssh -f text
```

On Windows:

```powershell
.\\chompedr.exe scan -r rules/ssh.yaml -i examples/ssh-demo.log --input-format ssh -f text
```

Expect two alerts. Live collection remains Linux-only:

```sh
./chompedr monitor
```

For Linux user installation from the extracted package, Python 3 is required but Rust is not:

```sh
python3 scripts/install-linux.py --binary ./chompedr
```

Add `--service` only if you want the optional disabled systemd user unit. See [Linux installation](linux-install.md) for activation, upgrades, and removal. That guide's source-build commands apply to a repository checkout; skip them when using a downloaded binary.

## Contents and compatibility

Each package contains `chompedr`, sample rules/events, Markdown documentation, `START-HERE.txt`, and `manifest.json`. Linux packages also include the user installer. The manifest records the application version, source commit, OS, architecture, build-platform description, and SHA-256 hashes of packaged content. Local packages are marked `local` unless a revision is explicitly supplied.

Builds use the current GitHub-hosted runners and native Rust toolchain. They are tested on those runners, not every OS release. In particular, Linux builds use the runner's GNU/glibc environment; Alpine/musl and older glibc versions are not promised compatible. CPU architecture names are `x86_64` and `aarch64` (ARM64). Match your machine and review `manifest.json`; build from source on your target system when compatibility is uncertain.

Packaging extracts the resulting archive, checks all manifest file hashes, and runs the packaged executable against the included SSH demo. This catches missing files, lost Unix executable permissions, and a broken archive layout. It also checks monitor help. Cross-version OS compatibility and publisher signing remain future release work.

For a local package after building a native release binary (Python 3.12+):

```sh
python scripts/package.py --output /absolute/path/to/new-output
```

The script refuses to overwrite an existing archive/checksum pair. It packages a fixed file list, not arbitrary workspace contents.
