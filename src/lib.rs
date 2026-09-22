//! Stateless detection over normalized JSON events. No endpoint actions are executed.
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;

pub type Result<T> = std::result::Result<T, String>;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFile {
    version: u32,
    rules: Vec<Rule>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub severity: Severity,
    #[serde(default = "enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub description: String,
    detection: Detection,
}

fn enabled() -> bool {
    true
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Detection {
    #[serde(default)]
    all: Vec<Condition>,
    #[serde(default)]
    any: Vec<Condition>,
    #[serde(default)]
    none: Vec<Condition>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Condition {
    field: String,
    op: Operator,
    value: Option<Value>,
    #[serde(default)]
    ignore_case: bool,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Operator {
    Equals,
    Contains,
    StartsWith,
    EndsWith,
    Regex,
    Exists,
}

struct CompiledCondition {
    path: Vec<String>,
    op: Operator,
    value: String,
    regex: Option<Regex>,
}

impl CompiledCondition {
    fn compile(c: Condition) -> Result<Self> {
        if c.field.trim().is_empty() || c.field.split('.').any(str::is_empty) {
            return Err("condition field must be a nonempty dotted path".into());
        }
        match c.op {
            Operator::Exists if c.ignore_case => {
                return Err("exists does not support ignore_case".into())
            }
            Operator::Exists if c.value.is_some() => return Err("exists must omit value".into()),
            Operator::Exists => (),
            _ if c
                .value
                .as_ref()
                .and_then(Value::as_str)
                .is_none_or(str::is_empty) =>
            {
                return Err("comparison operators require a nonempty string value".into());
            }
            _ => (),
        }
        let value = c
            .value
            .as_ref()
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let regex = if matches!(c.op, Operator::Regex) || c.ignore_case {
            let escaped = regex::escape(&value);
            let pattern = match c.op {
                Operator::Equals => format!(r"\A{escaped}\z"),
                Operator::StartsWith => format!(r"\A{escaped}"),
                Operator::EndsWith => format!(r"{escaped}\z"),
                Operator::Contains => escaped,
                Operator::Regex => value.clone(),
                Operator::Exists => unreachable!(),
            };
            Some(
                RegexBuilder::new(&pattern)
                    .case_insensitive(c.ignore_case)
                    .build()
                    .map_err(|e| format!("invalid regex: {e}"))?,
            )
        } else {
            None
        };
        Ok(Self {
            path: c.field.split('.').map(str::to_owned).collect(),
            op: c.op,
            value,
            regex,
        })
    }

    fn matches(&self, event: &Value) -> bool {
        let mut current = event;
        for part in &self.path {
            match current.as_object().and_then(|o| o.get(part)) {
                Some(v) => current = v,
                None => return false,
            }
        }
        if matches!(self.op, Operator::Exists) {
            return !current.is_null();
        }
        let Some(text) = current.as_str() else {
            return false;
        };
        if let Some(regex) = &self.regex {
            return regex.is_match(text);
        }
        match self.op {
            Operator::Equals => text == self.value,
            Operator::Contains => text.contains(&self.value),
            Operator::StartsWith => text.starts_with(&self.value),
            Operator::EndsWith => text.ends_with(&self.value),
            Operator::Regex => self.regex.as_ref().is_some_and(|r| r.is_match(text)),
            Operator::Exists => unreachable!(),
        }
    }
}

struct CompiledRule {
    metadata: Rule,
    all: Vec<CompiledCondition>,
    any: Vec<CompiledCondition>,
    none: Vec<CompiledCondition>,
}

pub struct Engine {
    rules: Vec<CompiledRule>,
}

#[derive(Debug, Serialize)]
pub struct Alert<'a> {
    pub rule_id: &'a str,
    pub rule_name: &'a str,
    pub severity: Severity,
    pub event: &'a Value,
}

impl Engine {
    /// Validate the entire rule set and compile regexes once, including disabled rules.
    pub fn from_yaml(source: &str) -> Result<Self> {
        let file: RuleFile =
            serde_yaml_ng::from_str(source).map_err(|e| format!("invalid YAML rules: {e}"))?;
        if file.version != 1 {
            return Err("unsupported rule schema version; expected 1".into());
        }
        if file.rules.is_empty() {
            return Err("rule set must contain at least one rule".into());
        }
        let mut ids = HashSet::new();
        let mut rules = Vec::new();
        for mut rule in file.rules {
            if rule.id.trim().is_empty() || rule.name.trim().is_empty() {
                return Err("rule id and name must not be blank".into());
            }
            if !ids.insert(rule.id.clone()) {
                return Err(format!("duplicate rule id: {}", rule.id));
            }
            if rule.detection.all.is_empty() && rule.detection.any.is_empty() {
                return Err(format!("rule {} has no detection conditions", rule.id));
            }
            let compile = |conditions: Vec<Condition>| -> Result<Vec<CompiledCondition>> {
                conditions
                    .into_iter()
                    .map(CompiledCondition::compile)
                    .collect()
            };
            let all = compile(std::mem::take(&mut rule.detection.all))
                .map_err(|e| format!("rule {}: {e}", rule.id))?;
            let any = compile(std::mem::take(&mut rule.detection.any))
                .map_err(|e| format!("rule {}: {e}", rule.id))?;
            let none = compile(std::mem::take(&mut rule.detection.none))
                .map_err(|e| format!("rule {}: {e}", rule.id))?;
            rules.push(CompiledRule {
                metadata: rule,
                all,
                any,
                none,
            });
        }
        Ok(Self { rules })
    }

    pub fn rules(&self) -> impl Iterator<Item = &Rule> {
        self.rules.iter().map(|r| &r.metadata)
    }

    /// Combine already validated sets; IDs must be unique across every set.
    pub fn combine(engines: impl IntoIterator<Item = Engine>) -> Result<Self> {
        let mut rules = Vec::new();
        let mut ids = HashSet::new();
        for engine in engines {
            for rule in engine.rules {
                if !ids.insert(rule.metadata.id.clone()) {
                    return Err(format!("duplicate rule id: {}", rule.metadata.id));
                }
                rules.push(rule);
            }
        }
        if rules.is_empty() {
            return Err("no rules loaded".into());
        }
        Ok(Self { rules })
    }

    /// Select exact IDs without enabling disabled rules. Validate all IDs first.
    pub fn select(&mut self, ids: &[String]) -> Result<()> {
        for id in ids {
            if !self.rules.iter().any(|r| &r.metadata.id == id) {
                return Err(format!("unknown rule id: {id}"));
            }
        }
        if !ids.is_empty() {
            self.rules.retain(|r| ids.contains(&r.metadata.id));
        }
        Ok(())
    }

    /// Emit all matching rules, in file order. Missing or mistyped fields never match.
    pub fn evaluate<'a>(&'a self, event: &'a Value) -> Vec<Alert<'a>> {
        if !event.is_object() {
            return Vec::new();
        }
        self.rules
            .iter()
            .filter(|r| {
                r.metadata.enabled
                    && r.all.iter().all(|c| c.matches(event))
                    && (r.any.is_empty() || r.any.iter().any(|c| c.matches(event)))
                    && !r.none.iter().any(|c| c.matches(event))
            })
            .map(|r| Alert {
                rule_id: &r.metadata.id,
                rule_name: &r.metadata.name,
                severity: r.metadata.severity,
                event,
            })
            .collect()
    }
}
