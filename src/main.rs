use chomp_edr::Engine;
use clap::{Parser, Subcommand, ValueEnum};
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::PathBuf;

const MAX_BYTES: usize = 1024 * 1024;

#[derive(Parser)]
#[command(
    name = "chomp",
    version,
    about = "Chomp EDR: YAML rules and JSON event detection"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Validate the YAML schema and compile every detection rule.
    Validate {
        #[arg(short, long)]
        rules: PathBuf,
    },
    /// List validated rule IDs, severity, and enabled status.
    ListRules {
        #[arg(short, long)]
        rules: PathBuf,
    },
    /// Evaluate JSON Lines events from a file or stdin; emit matching alerts.
    Scan {
        #[arg(short, long)]
        rules: PathBuf,
        /// JSON Lines input path; '-' reads stdin.
        #[arg(short, long, default_value = "-")]
        input: PathBuf,
        #[arg(short, long, value_enum, default_value = "json")]
        format: Format,
        /// Return exit code 1 when at least one alert is emitted.
        #[arg(long)]
        fail_on_alert: bool,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Json,
    Text,
}

fn load(path: PathBuf) -> Result<Engine, Box<dyn std::error::Error>> {
    let mut source = String::new();
    File::open(&path)?
        .take((MAX_BYTES + 1) as u64)
        .read_to_string(&mut source)?;
    if source.len() > MAX_BYTES {
        return Err("rule file exceeds 1 MiB".into());
    }
    Engine::from_yaml(&source).map_err(|e| format!("{}: {e}", path.display()).into())
}

fn run(cli: Cli) -> Result<u8, Box<dyn std::error::Error>> {
    let mut out = io::BufWriter::new(io::stdout().lock());
    match cli.command {
        Command::Validate { rules } => {
            let engine = load(rules)?;
            writeln!(out, "Valid: {} rule(s)", engine.rules().count())?;
        }
        Command::ListRules { rules } => {
            let engine = load(rules)?;
            for r in engine.rules() {
                writeln!(
                    out,
                    "{}\t{:?}\t{}\t{}",
                    r.id,
                    r.severity,
                    if r.enabled { "enabled" } else { "disabled" },
                    serde_json::to_string(&r.name)?
                )?;
            }
        }
        Command::Scan {
            rules,
            input,
            format,
            fail_on_alert,
        } => {
            let engine = load(rules)?;
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
                let event: serde_json::Value =
                    serde_json::from_str(&line).map_err(|e| format!("event line {number}: {e}"))?;
                if !event.is_object() {
                    return Err(format!("event line {number}: expected JSON object").into());
                }
                for alert in engine.evaluate(&event) {
                    found = true;
                    match format {
                        Format::Json => {
                            serde_json::to_writer(&mut out, &alert)?;
                            writeln!(out)?;
                        }
                        // JSON quoting escapes untrusted control characters for terminal output.
                        Format::Text => writeln!(
                            out,
                            "[{:?}] {} {} (line {})",
                            alert.severity,
                            serde_json::to_string(alert.rule_id)?,
                            serde_json::to_string(alert.rule_name)?,
                            number
                        )?,
                    }
                }
                out.flush()?;
            }
            out.flush()?;
            return Ok(u8::from(found && fail_on_alert));
        }
    }
    out.flush()?;
    Ok(0)
}

fn main() -> std::process::ExitCode {
    match run(Cli::parse()) {
        Ok(code) => code.into(),
        Err(e) => {
            if e.downcast_ref::<io::Error>()
                .is_some_and(|e| e.kind() == io::ErrorKind::BrokenPipe)
            {
                return std::process::ExitCode::SUCCESS;
            }
            eprintln!("chomp: {e}");
            2.into()
        }
    }
}
