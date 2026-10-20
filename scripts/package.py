"""Build and smoke-test a native CI snapshot archive from a release binary."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile

REPO = Path(__file__).resolve().parents[1]


def digest(path):
    with path.open("rb") as source:
        result = hashlib.sha256()
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            result.update(chunk)
        return result.hexdigest()


def run(binary, *args, cwd=None):
    return subprocess.run([str(binary), *args], cwd=cwd, capture_output=True, text=True, timeout=30)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=REPO / "dist")
    parser.add_argument("--revision", default=os.environ.get("GITHUB_SHA", "local"))
    args = parser.parse_args()
    if args.revision != "local" and not re.fullmatch(r"[0-9a-f]{40}", args.revision):
        parser.error("revision must be a full lowercase commit SHA or local")
    system = {"win32": "windows", "linux": "linux", "darwin": "macos"}.get(sys.platform)
    if system is None:
        parser.error("unsupported packaging platform")
    machine = platform.machine().lower()
    machine = {"amd64": "x86_64", "arm64": "aarch64"}.get(machine, machine)
    if machine not in ("x86_64", "aarch64"):
        parser.error("unsupported packaging architecture")
    executable = "chompedr.exe" if system == "windows" else "chompedr"
    source = REPO / "target/release" / executable
    version_result = run(source, "--version")
    version_match = re.fullmatch(r"chompedr ([0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?)", version_result.stdout.strip())
    if version_result.returncode != 0 or version_match is None:
        raise RuntimeError("Build the native release binary before packaging")
    version = version_match.group(1)
    name = f"chomp-edr-{version}-{system}-{machine}-{args.revision[:12]}"
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    archive = output / (name + (".zip" if system == "windows" else ".tar.gz"))
    checksum = Path(str(archive) + ".sha256")
    if archive.exists() or checksum.exists():
        raise RuntimeError("Package already exists; choose a fresh output directory")
    with tempfile.TemporaryDirectory(prefix="chomp-package-") as work:
        work = Path(work)
        package = work / name
        package.mkdir()
        shutil.copy2(source, package / executable)
        if system != "windows":
            (package / executable).chmod(0o755)
        files = [Path("README.md"), Path("examples/events.jsonl"), Path("examples/ssh-demo.log")]
        files += sorted(p.relative_to(REPO) for p in (REPO / "rules").glob("*.yaml"))
        files += sorted(p.relative_to(REPO) for p in (REPO / "docs").glob("*.md"))
        if system == "linux":
            files += [Path("scripts/install-linux.py"), Path("scripts/install-system-linux.py"),
                      Path("scripts/install-dashboard-linux.py"), Path("dashboard/server.py")]
            files += sorted(p.relative_to(REPO) for p in (REPO / "dashboard/web").iterdir() if p.is_file())
        for relative in files:
            target = package / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(REPO / relative, target)
        quickstart = f"""Chomp EDR {version} - {system} {machine}
CI snapshot: {args.revision}. This is an unsigned development build.

Extract this archive fully. Open a terminal in this folder.
Windows: .\\chompedr.exe --help
Linux/macOS: ./chompedr --help
Demo: {'.' + chr(92) + executable if system == 'windows' else './' + executable} scan -r rules/ssh.yaml -i examples/ssh-demo.log --input-format ssh -f text
Expected: two alerts from synthetic sample data.

Linux install (Python 3 required): python3 scripts/install-linux.py --binary ./chompedr
Live SSH collection is Linux-only. See docs/linux-install.md and docs/ssh-demo.md.
Linux dashboard: install the system collector binary first, then python3 scripts/install-dashboard-linux.py with sudo.
See docs/dashboard.md for service activation and SSH-tunnel access.
macOS and Windows can scan exported files. Running without arguments prints help and exits.
See docs/downloads.md for compatibility, checksums, and download instructions.
"""
        (package / "START-HERE.txt").write_text(quickstart, encoding="utf-8")
        manifest = {"version": version, "revision": args.revision, "os": system, "architecture": machine,
                    "build_platform": platform.platform(), "signed": False,
                    "files": {p.relative_to(package).as_posix(): digest(p) for p in sorted(package.rglob("*")) if p.is_file()}}
        (package / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        candidate = work / archive.name
        if system == "windows":
            with zipfile.ZipFile(candidate, "w", zipfile.ZIP_DEFLATED) as zipped:
                for path in sorted(package.rglob("*")):
                    if path.is_file():
                        zipped.write(path, path.relative_to(work).as_posix())
        else:
            with tarfile.open(candidate, "w:gz") as packed:
                packed.add(package, arcname=name)
        extracted = work / "extracted"
        extracted.mkdir()
        if system == "windows":
            with zipfile.ZipFile(candidate) as zipped:
                zipped.extractall(extracted)
        else:
            with tarfile.open(candidate) as packed:
                packed.extractall(extracted, filter="data")
        root = extracted / name
        recovered = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
        if recovered != manifest:
            raise RuntimeError("Archived manifest differs from staged manifest")
        for relative, expected in manifest["files"].items():
            if digest(root / relative) != expected:
                raise RuntimeError(f"Archive checksum mismatch: {relative}")
        binary = root / executable
        smoke = run(binary, "scan", "-r", "rules/ssh.yaml", "-i", "examples/ssh-demo.log",
                    "--input-format", "ssh", "--fail-on-alert", cwd=root)
        alerts = [json.loads(line) for line in smoke.stdout.splitlines()]
        if smoke.returncode != 1 or [a["rule_id"] for a in alerts] != ["CHOMP-SSH-001", "CHOMP-SSH-002"]:
            raise RuntimeError(f"Packaged executable failed demo: {smoke.stderr}")
        help_result = run(binary, "monitor", "--help", cwd=root)
        if help_result.returncode != 0 or "--status" not in help_result.stdout:
            raise RuntimeError("Packaged executable is missing monitor status")
        shutil.copyfile(candidate, archive)
        checksum.write_text(f"{digest(archive)}  {archive.name}\n", encoding="ascii")
        print(f"PASS: extracted {system}/{machine} archive, verified all file hashes, and ran the two-alert demo")
        print(f"Created {archive}")
        print(f"Created {checksum}")


if __name__ == "__main__":
    main()
