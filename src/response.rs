//! Response rule schema. Execution is handled by the separate Linux response service.
use crate::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub action: Action,
    pub target: Target,
    #[serde(default)]
    pub mode: Mode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Notify,
    BlockIp,
    TerminateProcess,
    QuarantineFile,
    SuspendProcess,
    IsolateHost,
    DisableAccount,
    DeleteFile,
    PreserveFile,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    DryRun,
    ApprovalRequired,
    Automatic,
}

/// Event field references, not literal targets or shell expressions.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum Target {
    Path {
        path: String,
    },
    Field {
        field: String,
    },
    Process {
        pid_field: String,
        start_time_field: String,
    },
}

impl Response {
    pub(crate) fn validate(&self) -> Result<()> {
        let valid_path = |path: &str| {
            path.split('.')
                .all(|part| !part.is_empty() && !part.chars().any(char::is_whitespace))
        };
        let process_action = matches!(
            self.action,
            Action::TerminateProcess | Action::SuspendProcess
        );
        match &self.target {
            Target::Path { path } if self.action == Action::PreserveFile
                && path.starts_with('/') && path != "/"
                && path.split('/').skip(1).all(|p| !p.is_empty() && p != "." && p != "..")
                && !path.chars().any(char::is_control) => (),
            Target::Field { field } if !process_action && self.action != Action::PreserveFile && valid_path(field) => (),
            Target::Process { pid_field, start_time_field }
                if process_action && valid_path(pid_field) && valid_path(start_time_field)
                    && pid_field != start_time_field => (),
            _ => return Err("response target requires an absolute path for preserve_file, a field path for other file/IP actions, or distinct pid_field and start_time_field paths for process actions".into()),
        }
        if let Some(duration) = &self.duration {
            if self.action != Action::BlockIp {
                return Err("response duration is supported only for block_ip".into());
            }
            let valid = duration
                .strip_suffix(['s', 'm', 'h', 'd'])
                .filter(|n| !n.is_empty() && n.bytes().all(|c| c.is_ascii_digit()))
                .and_then(|n| n.parse::<u32>().ok())
                .is_some_and(|n| n > 0);
            if !valid {
                return Err("response duration must be a positive integer followed by s, m, h or d (for example 15m)".into());
            }
        }
        Ok(())
    }
}
