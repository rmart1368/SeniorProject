# File and recursive-directory metadata monitoring

On Linux, select files or directories to watch. Directories are scanned recursively on every poll:

```sh
chompedr watch-files --path /etc/passwd --path /etc/shadow
chompedr watch-files --path /absolute/path/to/project
```

This is read-only monitoring: Chomp does not open watched files for content access, hash their contents, or change permissions. The default embedded rule emits a medium-severity review alert for every observed metadata transition on a selected path. Legitimate account management and software updates also match.

## Commands

```sh
# Faster polling, stopping after ten snapshots including the baseline.
chompedr watch-files --path /absolute/path/to/config --interval-ms 500 --samples 10

# Export normalized events instead of alerts.
chompedr watch-files --path /absolute/path/to/config --events > file-events.jsonl

# Evaluate exported observations on any supported platform.
chompedr scan -r rules/file-watch.yaml -i file-events.jsonl
```

Repeat `--path` to select 1..64 absolute paths. Parent (`..`) components are rejected; paths are not canonicalized through symlinks. Duplicate identical paths are watched once. Files can be absent at startup; their later creation is detected. Directories are traversed recursively, including subdirectories created after the baseline. Files in newly added or removed subtrees produce individual created/removed events. Overlapping roots produce one event per path. Directory metadata itself does not emit events. Explicit device/socket/FIFO paths are rejected; these special files inside a directory are skipped. Other metadata-access errors stop monitoring rather than being misreported as removal.

`--interval-ms` is 100..60000 ms, default 1000. The delay is between snapshots and excludes scan time. `--samples` includes the initial baseline, which never emits alerts. `--events` conflicts with custom `-r` rules; pipe or save raw events for custom scanning. Stop foreground monitoring with Ctrl+C. Run commands in your system terminal.

## Event meaning

Normalized events use `event.type: file_metadata_changed` and action `created`, `removed`, or `changed`. Their timestamp is observation time. `file.path` identifies the selected path. `file.before` and `file.after` contain size, numeric mode bits, owner/group IDs, inode/device numbers, modification/change timestamps in seconds and nanoseconds, and a symlink flag. Absent metadata is null. No contents or content hashes appear in events.

Directory traversal does not intentionally follow symlink entries, including links back to the watched root. A final-component symlink is watched as a link; changes to its target file are not followed. To watch that target's metadata, select the target path separately. Symlinks in parent directories still participate in normal OS path resolution. Replacing the selected path can change the inode even if its size is unchanged. Access timestamps are omitted, so merely reading a file does not trigger an alert from an atime update.

## Limits and deployment

Polling can miss changes between observations, including transient create/remove sequences or changes that leave the compared metadata unchanged. There is no cryptographic content validation, process attribution, write interception, or blocking. Reads across multiple paths are not atomic. A concurrent directory replacement can race traversal, so this is not a filesystem isolation boundary. Each poll is bounded to 100,000 discovered entries (including directories and overlapping discovery) and 128 levels below a selected root; exceeding a limit stops with an error rather than silently skipping files. Namespaces and path permissions affect visibility; monitoring does not elevate privileges. Metadata may still be visible even when file contents are unreadable.

Baselines and rule correlation are in memory only. Restarting establishes a new baseline and does not report changes made while stopped. This is separate from SSH journal checkpoints, `watch-processes`, and the optional SSH service. File monitoring is not automatically installed as a background service.

The Linux CI check uses disposable files only. It tests creation, chmod on an unreadable file, atomic replacement, removal, final-symlink behavior, suppression of unchanged snapshots, and raw-event replay through `scan`. Production-scale polling, filesystem-specific timestamp behavior, and permission arrangements still need target-host validation.

Recursive checks also cover overlapping roots, newly added/deleted subtrees, directory symlink loops, skipped FIFOs, and permission errors without false removal alerts.
