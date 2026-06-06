//! Hand-rolled command-line flag parsing for `luanti-server`.
//!
//! We deliberately avoid pulling in a dependency such as `clap` to keep
//! the dependency graph slim. The parser supports a small, fixed set of
//! `--key=value` and `--key value` flags, a `--help`/`-h` shortcut and
//! any positional arguments the caller wants to keep around for future
//! use.

use std::ffi::OsString;
use std::fmt;
use std::str::FromStr;

/// All authentication backends the server can be asked to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthDbMode {
    /// Persist users in a SQLite3 file inside the world directory.
    Sqlite3,
    /// Keep users in process memory only (no persistence).
    Memory,
    /// Store users in a remote PostgreSQL database.
    Postgres,
}

impl AuthDbMode {
    /// Canonical name used on the command line.
    pub fn as_str(&self) -> &'static str {
        match self {
            AuthDbMode::Sqlite3 => "sqlite3",
            AuthDbMode::Memory => "memory",
            AuthDbMode::Postgres => "postgres",
        }
    }

    /// Short, human-readable description shown in `--help` output.
    pub fn description(&self) -> &'static str {
        match self {
            AuthDbMode::Sqlite3 => "SQLite3 file inside the world directory (default)",
            AuthDbMode::Memory => "in-memory store, lost when the server stops",
            AuthDbMode::Postgres => "remote PostgreSQL server",
        }
    }
}

impl fmt::Display for AuthDbMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for AuthDbMode {
    type Err = CliError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "sqlite3" | "sqlite" => Ok(AuthDbMode::Sqlite3),
            "memory" | "mem" => Ok(AuthDbMode::Memory),
            "postgres" | "postgresql" | "pg" => Ok(AuthDbMode::Postgres),
            other => Err(CliError::InvalidValue {
                flag: "--auth-db-mode".to_string(),
                value: other.to_string(),
                hint: "expected one of: sqlite3, memory, postgres".to_string(),
            }),
        }
    }
}

/// Parsed, validated server configuration.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Authentication backend selected via `--auth-db-mode`.
    pub auth_db_mode: AuthDbMode,
    /// Extra positional arguments the parser did not consume.
    pub positionals: Vec<String>,
}

impl ServerConfig {
    /// Default configuration used when no flags are provided.
    pub fn default() -> Self {
        Self {
            auth_db_mode: AuthDbMode::Sqlite3,
            positionals: Vec::new(),
        }
    }
}

/// Errors produced while parsing the command line.
#[derive(Debug)]
pub enum CliError {
    /// A flag received a value that is not valid (e.g. unknown mode).
    InvalidValue {
        flag: String,
        value: String,
        hint: String,
    },
    /// A flag that requires a value was passed without one.
    MissingValue { flag: String },
    /// An unknown flag was passed.
    UnknownFlag { flag: String },
    /// `--help` was requested; the caller should print usage and exit.
    HelpRequested,
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::InvalidValue { flag, value, hint } => {
                write!(f, "invalid value '{}' for {}: {}", value, flag, hint)
            }
            CliError::MissingValue { flag } => write!(f, "{} requires a value", flag),
            CliError::UnknownFlag { flag } => write!(
                f,
                "unknown flag: {} (use --help for the list of supported flags)",
                flag
            ),
            CliError::HelpRequested => f.write_str("help requested"),
        }
    }
}

impl std::error::Error for CliError {}

/// Long-form usage banner, printed by `--help` and on bad CLI input.
pub fn print_help(program_name: &str) {
    let mut modes = String::new();
    for mode in [
        AuthDbMode::Sqlite3,
        AuthDbMode::Memory,
        AuthDbMode::Postgres,
    ] {
        modes.push_str(&format!(
            "    {:<10} {}\n",
            mode.as_str(),
            mode.description()
        ));
    }

    println!(
        "{program_name} - Luanti (Minetest) server, Rust implementation\n\
         \n\
         USAGE:\n\
             {program_name} [OPTIONS]\n\
         \n\
         OPTIONS:\n\
             -h, --help                       Print this help and exit\n\
             --auth-db-mode <MODE>            Authentication backend to use\n\
                                             <MODE> is one of:\n\
         {modes}\n\
             --world-dir <DIR>                World directory for sqlite3 backend\n\
                                             (default: ./world)\n\
         \n\
         ENVIRONMENT:\n\
             LUANTI_PG_CONN                   PostgreSQL connection string used\n\
                                             when --auth-db-mode=postgres\n\
         \n\
         EXAMPLES:\n\
             # default (sqlite3 in ./world)\n\
             {program_name}\n\
             # ephemeral server, no persistence\n\
             {program_name} --auth-db-mode=memory\n\
             # PostgreSQL backend\n\
             LUANTI_PG_CONN='host=localhost user=minetest dbname=minetest' \\\n\
                 {program_name} --auth-db-mode=postgres\n",
        program_name = program_name,
        modes = modes,
    );
}

/// Parse a slice of `OsString` arguments into a [`ServerConfig`].
///
/// On `--help` / `-h` this returns [`CliError::HelpRequested`].
pub fn parse_args<I, S>(args: I) -> Result<ServerConfig, CliError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut config = ServerConfig::default();
    let iter: Vec<String> = args.into_iter().map(|s| s.as_ref().to_owned()).collect();

    let mut i = 0;
    while i < iter.len() {
        let arg = iter[i].as_str();
        match arg {
            "-h" | "--help" => return Err(CliError::HelpRequested),
            "--auth-db-mode" => {
                let value = iter.get(i + 1).ok_or_else(|| CliError::MissingValue {
                    flag: "--auth-db-mode".to_string(),
                })?;
                config.auth_db_mode = AuthDbMode::from_str(value)?;
                i += 2;
            }
            "--world-dir" => {
                let value = iter.get(i + 1).ok_or_else(|| CliError::MissingValue {
                    flag: "--world-dir".to_string(),
                })?;
                config.positionals.push(format!("--world-dir={}", value));
                i += 2;
            }
            other if other.starts_with("--auth-db-mode=") => {
                let value = &other["--auth-db-mode=".len()..];
                config.auth_db_mode = AuthDbMode::from_str(value)?;
                i += 1;
            }
            other if other.starts_with("--world-dir=") => {
                let value = &other["--world-dir=".len()..];
                config.positionals.push(format!("--world-dir={}", value));
                i += 1;
            }
            other if other.starts_with("--") => {
                return Err(CliError::UnknownFlag {
                    flag: other.to_string(),
                });
            }
            other => {
                config.positionals.push(other.to_string());
                i += 1;
            }
        }
    }

    Ok(config)
}

/// Convenience wrapper: parse `std::env::args_os()` skipping argv[0].
///
/// `program_name` is used in help/error output. If the program name
/// cannot be determined from the path, pass a literal such as
/// `"luanti-server"`.
pub fn parse_env(program_name: &str) -> Result<ServerConfig, CliError> {
    let mut raw: Vec<OsString> = std::env::args_os().collect();
    if !raw.is_empty() {
        raw.remove(0);
    }
    let strs: Vec<String> = raw
        .into_iter()
        .map(|s| s.to_string_lossy().into_owned())
        .collect();
    let config = parse_args(strs)?;
    let _ = program_name;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_sqlite() {
        let cfg = parse_args(Vec::<&str>::new()).unwrap();
        assert_eq!(cfg.auth_db_mode, AuthDbMode::Sqlite3);
        assert!(cfg.positionals.is_empty());
    }

    #[test]
    fn space_separated_value() {
        let cfg = parse_args(["--auth-db-mode", "memory"]).unwrap();
        assert_eq!(cfg.auth_db_mode, AuthDbMode::Memory);
    }

    #[test]
    fn equals_separated_value() {
        let cfg = parse_args(["--auth-db-mode=postgres"]).unwrap();
        assert_eq!(cfg.auth_db_mode, AuthDbMode::Postgres);
    }

    #[test]
    fn accepts_aliases() {
        for (raw, expected) in [
            ("sqlite", AuthDbMode::Sqlite3),
            ("sqlite3", AuthDbMode::Sqlite3),
            ("mem", AuthDbMode::Memory),
            ("memory", AuthDbMode::Memory),
            ("pg", AuthDbMode::Postgres),
            ("postgres", AuthDbMode::Postgres),
            ("postgresql", AuthDbMode::Postgres),
        ] {
            let cfg = parse_args([format!("--auth-db-mode={}", raw)]).unwrap();
            assert_eq!(cfg.auth_db_mode, expected, "raw = {}", raw);
        }
    }

    #[test]
    fn invalid_value_errors() {
        let err = parse_args(["--auth-db-mode=mongodb"]).unwrap_err();
        match err {
            CliError::InvalidValue { flag, value, .. } => {
                assert_eq!(flag, "--auth-db-mode");
                assert_eq!(value, "mongodb");
            }
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn missing_value_errors() {
        let err = parse_args(["--auth-db-mode"]).unwrap_err();
        assert!(matches!(err, CliError::MissingValue { .. }));
    }

    #[test]
    fn help_flag_short_and_long() {
        for flag in ["-h", "--help"] {
            let err = parse_args([flag]).unwrap_err();
            assert!(matches!(err, CliError::HelpRequested));
        }
    }

    #[test]
    fn unknown_flag_errors() {
        let err = parse_args(["--no-such-flag"]).unwrap_err();
        match err {
            CliError::UnknownFlag { flag } => assert_eq!(flag, "--no-such-flag"),
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn positionals_are_kept() {
        let cfg = parse_args(["--auth-db-mode=memory", "extra", "args"]).unwrap();
        assert_eq!(cfg.auth_db_mode, AuthDbMode::Memory);
        assert_eq!(cfg.positionals, vec!["extra", "args"]);
    }

    #[test]
    fn world_dir_is_recorded() {
        let cfg = parse_args(["--world-dir", "/tmp/world"]).unwrap();
        assert_eq!(cfg.positionals, vec!["--world-dir=/tmp/world"]);
    }

    #[test]
    fn from_str_round_trip() {
        for mode in [
            AuthDbMode::Sqlite3,
            AuthDbMode::Memory,
            AuthDbMode::Postgres,
        ] {
            let parsed = AuthDbMode::from_str(mode.as_str()).unwrap();
            assert_eq!(parsed, mode);
            assert_eq!(parsed.to_string(), mode.as_str());
        }
    }
}
