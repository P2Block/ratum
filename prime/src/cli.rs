use crate::config::{self, Config};
use clap::Parser as _;
use log::warn;
use std::fmt::Display;
use std::path::{Path, PathBuf};

pub const USAGE_EXIT: i32 = 2;

macro_rules! fatal {
    ($($arg:tt)*) => {{
        eprintln!($($arg)*);
        std::process::exit($crate::cli::USAGE_EXIT);
    }};
}

pub(crate) use fatal;

pub struct Invocation {
    pub command_line: Config,
    pub file: Config,
}

pub fn load() -> Invocation {
    let command_line = Config::parse();
    let path = match (&command_line.config, &command_line.data_dir) {
        (Some(p), _) => Some(PathBuf::from(p)),
        (None, Some(dir)) => Some(PathBuf::from(dir).join("ratum.toml")),
        (None, None) => None,
    };
    let file = match path {
        Some(path) => load_file(&path, command_line.config.is_some()),
        None => Config::default(),
    };
    Invocation { command_line, file }
}

fn load_file(path: &Path, required: bool) -> Config {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && !required => {
            return Config::default();
        }
        Err(e) => fatal!("cannot read {}: {e}", path.display()),
    };
    match config::parse_toml(&text) {
        Ok(c) => {
            warn_if_readable(path, &c);
            c
        }
        Err(e) => fatal!("{}: {e}", path.display()),
    }
}

pub fn resolve<T: Display>(
    cli: Option<T>,
    file: Option<T>,
    default: T,
    flag: &str,
    must_be: &str,
    ok: impl Fn(&T) -> bool,
) -> T {
    resolve_opt(cli, file, flag, must_be, ok).unwrap_or(default)
}

pub fn resolve_opt<T: Display>(
    cli: Option<T>,
    file: Option<T>,
    flag: &str,
    must_be: &str,
    ok: impl Fn(&T) -> bool,
) -> Option<T> {
    let value = cli.or(file)?;
    if !ok(&value) {
        fatal!("{flag} must be {must_be}, got {value}");
    }
    Some(value)
}

pub fn resolve_str(cli: Option<String>, file: Option<String>, default: &str) -> String {
    cli.or(file).unwrap_or_else(|| default.to_string())
}

#[cfg(unix)]
fn warn_if_readable(path: &Path, settings: &Config) {
    use std::os::unix::fs::PermissionsExt as _;
    if !settings.holds_a_secret() {
        return;
    }
    let Ok(mode) = std::fs::metadata(path).map(|m| m.permissions().mode()) else { return };
    if mode & 0o077 != 0 {
        warn!(
            "{} holds a password and is readable by more than its owner (mode {:03o}); \
             chmod 600 it",
            path.display(),
            mode & 0o777
        );
    }
}

#[cfg(not(unix))]
fn warn_if_readable(_path: &Path, _settings: &Config) {}
