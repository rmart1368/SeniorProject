use chomp_edr::Engine;
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::collections::HashSet;
use std::fs::File;
use std::io::{self, BufRead, BufReader, IsTerminal, Read, Write};
use std::path::PathBuf;

const MAX_BYTES: usize = 1024 * 1024;

#[derive(Parser)]
#[command(
    name = "chompedr",
    version,
    about = "Chomp EDR: YAML rules and JSON event detection"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Watch Linux files or recursive directories for metadata changes without reading contents.
    WatchFiles {
        /// Absolute file or directory path; directories are recursive. Repeat for up to 64 roots.
        #[arg(long = "path", required = true)]
        paths: Vec<PathBuf>,
        #[arg(long, default_value_t = 1000, value_parser = clap::value_parser!(u64).range(100..=60000))]
        interval_ms: u64,
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
        samples: Option<u64>,
        /// Emit raw observation events instead of alerts.
        #[arg(long, conflicts_with_all = ["rules", "rule_paths"])]
        events: bool,
        #[command(flatten)]
        source: RuleSource,
    },
    /// Poll Linux processes and emit review alerts (or raw observation events).
    WatchProcesses {
        #[arg(long, default_value_t = 1000, value_parser = clap::value_parser!(u64).range(100..=60000))]
        interval_ms: u64,
        /// Stop after this many snapshots, including the initial baseline.
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
        samples: Option<u64>,
        /// Emit observations for processes already present in the first snapshot.
        #[arg(long)]
        include_existing: bool,
        /// Emit raw JSON events instead of alerts; pipe them to scan for custom processing.
        #[arg(long, conflicts_with_all = ["rules", "rule_paths"])]
        events: bool,
        /// Override the embedded process review rules.
        #[command(flatten)]
        source: RuleSource,
    },
    /// Monitor Linux SSH journal records with automatic checkpoint recovery.
    Monitor {
        /// YAML sources; omit to use the built-in SSH rules.
        #[command(flatten)]
        source: RuleSource,
        /// Checkpoint directory; defaults to your user state directory.
        #[arg(long)]
        checkpoint: Option<PathBuf>,
        /// Inspect saved progress without starting a collector (JSON output).
        #[arg(long, conflicts_with = "once")]
        status: bool,
        /// Process available records and exit instead of following new records.
        #[arg(long)]
        once: bool,
    },
    /// Validate supplied YAML and list rule metadata, including disabled rules.
    Validate {
        #[command(flatten)]
        source: RuleSource,
        #[arg(short, long, value_enum, default_value = "text")]
        format: Format,
    },
    /// List every bundled YAML file and its enabled and disabled rules.
    ListRules {
        #[arg(short, long, value_enum, default_value = "text")]
        format: Format,
    },
    /// Export embedded rule metadata and original YAML as one JSON document.
    ExportRules,
    /// Evaluate JSON Lines events from a file or stdin; emit matching alerts.
    Scan {
        #[arg(long, value_enum, default_value = "json")]
        input_format: InputFormat,
        #[command(flatten)]
        source: RuleSource,
        /// Select an exact rule ID; repeat to select multiple rules.
        #[arg(long = "rule")]
        rule_ids: Vec<String>,
        /// JSON Lines input path; '-' reads stdin.
        #[arg(short, long, default_value = "-")]
        input: PathBuf,
        #[arg(short, long, value_enum, default_value = "json")]
        format: Format,
        /// Return exit code 1 when at least one alert is emitted.
        #[arg(long)]
        fail_on_alert: bool,
        /// Save journal progress and correlation in this directory; replay input through the saved cursor on restart.
        #[arg(long)]
        checkpoint: Option<PathBuf>,
    },
}

#[derive(Args)]
struct RuleSource {
    /// YAML file or directory (nonrecursive); repeat to load multiple sources.
    #[arg(short, long)]
    rules: Vec<PathBuf>,
    /// Rule files or directories; --rules is optional.
    #[arg(value_name = "RULES")]
    rule_paths: Vec<PathBuf>,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Json,
    Text,
}

#[derive(Clone, Copy, ValueEnum)]
enum InputFormat {
    Json,
    Ssh,
    Journal,
}

fn load_file(path: PathBuf) -> Result<Engine, Box<dyn std::error::Error>> {
    let mut source = String::new();
    File::open(&path)?
        .take((MAX_BYTES + 1) as u64)
        .read_to_string(&mut source)?;
    if source.len() > MAX_BYTES {
        return Err("rule file exceeds 1 MiB".into());
    }
    Engine::from_yaml(&source).map_err(|e| format!("{}: {e}", path.display()).into())
}

fn load(source: RuleSource) -> Result<Engine, Box<dyn std::error::Error>> {
    let mut paths = Vec::new();
    let mut seen = HashSet::new();
    for path in source.rules.into_iter().chain(source.rule_paths) {
        let mut files = if path.is_dir() {
            let mut files = Vec::new();
            for entry in std::fs::read_dir(&path)? {
                let entry = entry?;
                let p = entry.path();
                if entry.file_type()?.is_file()
                    && p.extension().and_then(|s| s.to_str()).is_some_and(|s| {
                        s.eq_ignore_ascii_case("yaml") || s.eq_ignore_ascii_case("yml")
                    })
                {
                    files.push(p);
                }
            }
            if files.is_empty() {
                return Err(format!("{}: no YAML rule files", path.display()).into());
            }
            files.sort();
            files
        } else {
            vec![path]
        };
        for file in files.drain(..) {
            let canonical = file.canonicalize()?;
            if seen.insert(canonical) {
                paths.push(file);
            }
        }
    }
    if paths.is_empty() {
        return Err("provide a rule file or directory (positional or --rules)".into());
    }
    let mut engines = Vec::new();
    for path in paths {
        engines.push(load_file(path)?);
    }
    Engine::combine(engines).map_err(Into::into)
}

// Generated from all immediate .yaml files in the project's internal rules directory.
include!(concat!(env!("OUT_DIR"), "/bundled_rules.rs"));

fn list_internal_rules(
    out: &mut impl Write,
    format: Format,
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = std::env::current_exe()?
        .parent()
        .ok_or("executable has no parent")?
        .join("rules");
    let mut files = Vec::new();
    if directory.try_exists()? {
        for entry in std::fs::read_dir(&directory)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_file()
                && path
                    .extension()
                    .and_then(|s| s.to_str())
                    .is_some_and(|s| s.eq_ignore_ascii_case("yaml"))
            {
                files.push(path);
            }
        }
        files.sort();
        if files.is_empty() {
            return Err(format!("{}: no .yaml rule files", directory.display()).into());
        }
    }
    let engines = if directory.try_exists()? {
        files
            .into_iter()
            .map(|path| {
                let name = path.file_name().unwrap().to_string_lossy().into_owned();
                load_file(path).map(|engine| (name, engine))
            })
            .collect::<Result<Vec<_>, _>>()?
    } else {
        BUNDLED_RULES
            .iter()
            .map(|(name, yaml)| {
                Engine::from_yaml(yaml)
                    .map(|engine| (name.to_string(), engine))
                    .map_err(|e| format!("{name}: {e}").into())
            })
            .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?
    };
    for (file, engine) in engines {
        if matches!(format, Format::Text) {
            writeln!(out, "{}", serde_json::to_string(&file)?)?;
        }
        for rule in engine.rules() {
            if matches!(format, Format::Json) {
                serde_json::to_writer(
                    &mut *out,
                    &serde_json::json!({"file": file, "id": rule.id, "name": rule.name, "enabled": rule.enabled}),
                )?;
                writeln!(out)?;
            } else {
                writeln!(
                    out,
                    "  {}\t{}\t{}",
                    serde_json::to_string(&rule.id)?,
                    if rule.enabled { "enabled" } else { "disabled" },
                    serde_json::to_string(&rule.name)?
                )?;
            }
        }
    }
    Ok(())
}

/// Always inspect compiled defaults, even when a rules directory exists beside the binary.
fn export_embedded_rules(out: &mut impl Write) -> Result<(), Box<dyn std::error::Error>> {
    let mut files = Vec::new();
    for (file, yaml) in BUNDLED_RULES {
        let engine = Engine::from_yaml(yaml)?;
        let rules: Vec<_> = engine
            .rules()
            .map(|r| {
                serde_json::json!({
                    "id": r.id, "name": r.name, "description": r.description,
                    "severity": r.severity, "enabled": r.enabled,
                    "threshold": r.threshold.as_ref().map(|t| serde_json::json!({
                        "count": t.count, "window_seconds": t.window_seconds,
                        "group_by": t.group_by
                    }))
                })
            })
            .collect();
        files.push(serde_json::json!({"file": file, "yaml": yaml, "rules": rules}));
    }
    serde_json::to_writer(
        &mut *out,
        &serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"), "source": "embedded", "files": files
        }),
    )?;
    writeln!(out)?;
    Ok(())
}

fn run(cli: Cli) -> Result<u8, Box<dyn std::error::Error>> {
    let mut out = io::BufWriter::new(io::stdout().lock());
    match cli.command {
        Command::WatchFiles {
            paths,
            interval_ms,
            samples,
            events,
            source,
        } => {
            let engine = if source.rules.is_empty() && source.rule_paths.is_empty() {
                Engine::from_yaml(include_str!("../rules/file-watch.yaml"))?
            } else {
                load(source)?
            };
            let mut session = chomp_edr::session::Session::new(engine);
            chomp_edr::files::watch(paths, interval_ms, samples, |event| {
                let rows = if events {
                    vec![event.clone()]
                } else {
                    session.process(event)?
                };
                for row in rows {
                    serde_json::to_writer(&mut out, &row).map_err(|e| e.to_string())?;
                    writeln!(out).map_err(|e| e.to_string())?;
                }
                out.flush().map_err(|e| e.to_string())
            })?;
        }

        Command::WatchProcesses {
            interval_ms,
            samples,
            include_existing,
            events,
            source,
        } => {
            let engine = if source.rules.is_empty() && source.rule_paths.is_empty() {
                Engine::from_yaml(include_str!("../rules/processes.yaml"))?
            } else {
                load(source)?
            };
            let mut session = chomp_edr::session::Session::new(engine);
            chomp_edr::processes::collect(interval_ms, samples, include_existing, |event| {
                let rows = if events {
                    vec![event.clone()]
                } else {
                    session.process(event)?
                };
                for row in rows {
                    serde_json::to_writer(&mut out, &row).map_err(|e| e.to_string())?;
                    writeln!(out).map_err(|e| e.to_string())?;
                }
                out.flush().map_err(|e| e.to_string())
            })?;
        }

        Command::Monitor {
            source,
            checkpoint,
            once,
            status,
        } => {
            let engine = if source.rules.is_empty() && source.rule_paths.is_empty() {
                Engine::from_yaml(include_str!("../rules/ssh.yaml"))?
            } else {
                load(source)?
            };
            if status {
                let dir = chomp_edr::monitor::state_directory(checkpoint)?;
                let state = chomp_edr::checkpoint::status(engine, &dir)?;
                serde_json::to_writer(&mut out, &state)?;
                writeln!(out)?;
            } else {
                let output =
                    chomp_edr::terminal::AlertOutput::new(&mut out, io::stdout().is_terminal());
                chomp_edr::monitor::run(engine, checkpoint, once, output)
                    .map_err(|e| format!("monitor: {e}"))?;
            }
        }
        Command::ExportRules => export_embedded_rules(&mut out)?,
        Command::ListRules { format } => {
            list_internal_rules(&mut out, format)?;
        }
        Command::Validate { source, format } => {
            let engine = load(source)?;
            for r in engine.rules() {
                if matches!(format, Format::Json) {
                    serde_json::to_writer(
                        &mut out,
                        &serde_json::json!({
                            "id": r.id, "name": r.name, "description": r.description,
                            "severity": r.severity, "enabled": r.enabled
                        }),
                    )?;
                    writeln!(out)?;
                    continue;
                }
                writeln!(
                    out,
                    "{}\t{:?}\t{}\t{}",
                    serde_json::to_string(&r.id)?,
                    r.severity,
                    if r.enabled { "enabled" } else { "disabled" },
                    serde_json::to_string(&r.name)?
                )?;
            }
        }
        Command::Scan {
            input_format,
            source,
            rule_ids,
            input,
            format,
            fail_on_alert,
            checkpoint,
        } => {
            let mut engine = load(source)?;
            engine.select(&rule_ids)?;
            if let Some(path) = checkpoint {
                if !matches!(input_format, InputFormat::Journal) || !matches!(format, Format::Json)
                {
                    return Err(
                        "--checkpoint requires --input-format journal and JSON output".into(),
                    );
                }
                let reader: Box<dyn BufRead> = if input.as_os_str() == "-" {
                    Box::new(BufReader::new(io::stdin()))
                } else {
                    Box::new(BufReader::new(File::open(&input)?))
                };
                let found = chomp_edr::checkpoint::scan(engine, &path, reader, &mut out)
                    .map_err(|e| format!("checkpoint scan: {e}"))?;
                return Ok(u8::from(found && fail_on_alert));
            }
            let mut session = chomp_edr::session::Session::new(engine);
            let mut skipped = 0;
            let mut reader: Box<dyn BufRead> = if input.as_os_str() == "-" {
                Box::new(BufReader::new(io::stdin()))
            } else {
                Box::new(BufReader::new(File::open(&input)?))
            };
            let mut line = String::new();
            let mut number = 0;
            let mut found = false;
            loop {
                line.clear();
                let bytes = reader
                    .by_ref()
                    .take((MAX_BYTES + 1) as u64)
                    .read_line(&mut line)?;
                if bytes == 0 {
                    break;
                }
                number += 1;
                if bytes > MAX_BYTES {
                    return Err(format!("event line {number} exceeds 1 MiB").into());
                }
                if line.trim().is_empty() {
                    continue;
                }
                let event: serde_json::Value = match input_format {
                    InputFormat::Json => serde_json::from_str(&line)
                        .map_err(|e| format!("event line {number}: {e}"))?,
                    InputFormat::Ssh | InputFormat::Journal => match (match input_format {
                        InputFormat::Journal => chomp_edr::ssh::parse_journal(&line),
                        _ => chomp_edr::ssh::parse(&line),
                    })
                    .map_err(|e| format!("log line {number}: {e}"))?
                    {
                        Some(event) => event,
                        None => {
                            skipped += 1;
                            continue;
                        }
                    },
                };
                if !event.is_object() {
                    return Err(format!("event line {number}: expected JSON object").into());
                }
                for alert in session
                    .process(&event)
                    .map_err(|e| format!("event line {number}: {e}"))?
                {
                    found = true;
                    match format {
                        Format::Json => {
                            serde_json::to_writer(&mut out, &alert)?;
                            writeln!(out)?;
                        }
                        // JSON quoting escapes untrusted control characters for terminal output.
                        Format::Text => writeln!(
                            out,
                            "[{}] {} {} (line {})",
                            alert["severity"].as_str().unwrap_or("unknown"),
                            alert["rule_id"],
                            alert["rule_name"],
                            number
                        )?,
                    }
                }
                out.flush()?;
            }
            out.flush()?;
            if !matches!(input_format, InputFormat::Json) {
                eprintln!("Skipped {skipped} unrelated log line(s).");
            }
            return Ok(u8::from(found && fail_on_alert));
        }
    }
    out.flush()?;
    Ok(0)
}

fn main() -> std::process::ExitCode {
    let cli = if std::env::args_os().len() == 1 {
        Cli::parse_from(["chompedr", "--help"])
    } else {
        Cli::parse()
    };
    match run(cli) {
        Ok(code) => code.into(),
        Err(e) => {
            if e.downcast_ref::<io::Error>()
                .is_some_and(|e| e.kind() == io::ErrorKind::BrokenPipe)
            {
                return std::process::ExitCode::SUCCESS;
            }
            eprintln!("chompedr: {e}");
            2.into()
        }
    }
}
