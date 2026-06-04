//! Luanti Authentication Database Library
//!
//! This library provides authentication database support for Luanti (formerly Minetest).
//! It supports SQLite3 and PostgreSQL backends, compatible with the C++ implementation.
//!
//! # Example
//!
//! ```no_run
//! use luanti_auth_db::{AuthDatabase, AuthEntry};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! #[cfg(feature = "sqlite")]
//! {
//!     let mut db = luanti_auth_db::sqlite::AuthDatabaseSqlite::new("./world")?;
//!     
//!     // Create a new user
//!     let mut auth_entry = AuthEntry {
//!         id: 0,
//!         name: "player1".to_string(),
//!         password: "hashed_password".to_string(),
//!         privileges: vec!["interact".to_string(), "shout".to_string()],
//!         last_login: 0,
//!     };
//!     
//!     db.create_auth(&mut auth_entry)?;
//!     
//!     // Get user authentication
//!     let auth = db.get_auth("player1")?;
//!     println!("User ID: {}", auth.id);
//! }
//! # Ok(())
//! # }
//! ```

use thiserror::Error;

/// Authentication entry structure
/// Compatible with C++ struct AuthEntry
#[derive(Debug, Clone, PartialEq)]
pub struct AuthEntry {
    /// User ID (auto-incremented)
    pub id: u64,
    /// Username
    pub name: String,
    /// Password hash
    pub password: String,
    /// List of privileges
    pub privileges: Vec<String>,
    /// Last login timestamp (Unix time)
    pub last_login: i64,
}

/// Authentication database errors
#[derive(Error, Debug)]
pub enum AuthDbError {
    #[error("User not found: {0}")]
    UserNotFound(String),

    #[error("User already exists: {0}")]
    UserAlreadyExists(String),

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Connection error: {0}")]
    ConnectionError(String),

    #[cfg(feature = "sqlite")]
    #[error("SQLite error: {0}")]
    SqliteError(#[from] rusqlite::Error),

    #[cfg(feature = "postgres")]
    #[error("PostgreSQL error: {0}")]
    PostgresError(#[from] tokio_postgres::Error),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, AuthDbError>;

/// Authentication database trait
///
/// This trait defines the interface for authentication databases.
/// Implementations must be compatible with the C++ AuthDatabase interface.
pub trait AuthDatabase {
    /// Get authentication entry by username
    fn get_auth(&mut self, name: &str) -> Result<AuthEntry>;

    /// Save (update) an existing authentication entry
    fn save_auth(&mut self, auth_entry: &AuthEntry) -> Result<()>;

    /// Create a new authentication entry
    /// The id field will be populated with the auto-generated ID
    fn create_auth(&mut self, auth_entry: &mut AuthEntry) -> Result<()>;

    /// Delete authentication entry by username
    fn delete_auth(&mut self, name: &str) -> Result<bool>;

    /// List all usernames
    fn list_names(&mut self) -> Result<Vec<String>>;

    /// Reload database (for file-based backends)
    fn reload(&self) -> Result<()>;
}

#[cfg(feature = "sqlite")]
pub mod sqlite;

#[cfg(feature = "postgres")]
pub mod postgres;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_entry_creation() {
        let entry = AuthEntry {
            id: 1,
            name: "testuser".to_string(),
            password: "hashed_pass".to_string(),
            privileges: vec!["interact".to_string()],
            last_login: 1234567890,
        };

        assert_eq!(entry.id, 1);
        assert_eq!(entry.name, "testuser");
        assert_eq!(entry.privileges.len(), 1);
    }
}
