//! SQLite3 authentication database implementation
//!
//! Compatible with the C++ AuthDatabaseSQLite3 class.

use crate::{AuthDatabase, AuthDbError, AuthEntry, Result};
use log::{debug, error};
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use std::path::Path;

/// SQLite3 authentication database
///
/// Creates and manages an auth.sqlite database in the specified directory.
/// Schema is compatible with the C++ implementation.
pub struct AuthDatabaseSqlite {
    conn: Connection,
}

impl AuthDatabaseSqlite {
    /// Create or open the authentication database
    ///
    /// # Arguments
    /// * `savedir` - Directory where auth.sqlite will be created/opened
    ///
    /// # Example
    /// ```no_run
    /// # use luanti_auth_db::sqlite::AuthDatabaseSqlite;
    /// let db = AuthDatabaseSqlite::new("./world").unwrap();
    /// ```
    pub fn new<P: AsRef<Path>>(savedir: P) -> Result<Self> {
        let db_path = savedir.as_ref().join("auth.sqlite");
        debug!("Opening auth database at: {:?}", db_path);

        let conn = Connection::open(&db_path).map_err(|e| {
            error!("Failed to open auth database: {}", e);
            e
        })?;

        let db = AuthDatabaseSqlite { conn };
        db.create_database()?;
        Ok(db)
    }

    /// Create database tables if they don't exist
    fn create_database(&self) -> Result<()> {
        // Create auth table
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS `auth` (
                `id` INTEGER PRIMARY KEY AUTOINCREMENT,
                `name` TEXT UNIQUE NOT NULL,
                `password` TEXT NOT NULL,
                `last_login` INTEGER NOT NULL DEFAULT 0
            )",
            [],
        )?;

        // Create user_privileges table
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS `user_privileges` (
                `id` INTEGER,
                `privilege` TEXT,
                PRIMARY KEY (id, privilege),
                CONSTRAINT fk_id FOREIGN KEY (id) REFERENCES auth (id) ON DELETE CASCADE
            )",
            [],
        )?;

        debug!("Auth database tables created/verified");
        Ok(())
    }

    /// Write privileges for an auth entry
    fn write_privileges(tx: &Transaction, auth_entry: &AuthEntry) -> Result<()> {
        // Delete existing privileges
        tx.execute(
            "DELETE FROM user_privileges WHERE id = ?",
            params![auth_entry.id],
        )?;

        // Insert new privileges
        for privilege in &auth_entry.privileges {
            tx.execute(
                "INSERT OR IGNORE INTO user_privileges (id, privilege) VALUES (?, ?)",
                params![auth_entry.id, privilege],
            )?;
        }

        Ok(())
    }

    /// Read privileges for an auth entry
    fn read_privileges(&self, auth_id: u64) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT privilege FROM user_privileges WHERE id = ?")?;

        let privileges = stmt
            .query_map(params![auth_id], |row| row.get(0))?
            .collect::<std::result::Result<Vec<String>, _>>()?;

        Ok(privileges)
    }
}

impl AuthDatabase for AuthDatabaseSqlite {
    fn get_auth(&mut self, name: &str) -> Result<AuthEntry> {
        debug!("Getting auth for user: {}", name);

        let mut stmt = self
            .conn
            .prepare("SELECT id, name, password, last_login FROM auth WHERE name = ?")?;

        let auth_entry = stmt
            .query_row(params![name], |row| {
                Ok(AuthEntry {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    password: row.get(2)?,
                    privileges: Vec::new(), // Will be filled below
                    last_login: row.get(3)?,
                })
            })
            .optional()?;

        match auth_entry {
            Some(mut entry) => {
                entry.privileges = self.read_privileges(entry.id)?;
                Ok(entry)
            }
            None => Err(AuthDbError::UserNotFound(name.to_string())),
        }
    }

    fn save_auth(&mut self, auth_entry: &AuthEntry) -> Result<()> {
        debug!("Saving auth for user: {}", auth_entry.name);

        let tx = self.conn.transaction()?;

        tx.execute(
            "UPDATE auth SET name = ?, password = ?, last_login = ? WHERE id = ?",
            params![
                auth_entry.name,
                auth_entry.password,
                auth_entry.last_login,
                auth_entry.id
            ],
        )?;

        Self::write_privileges(&tx, auth_entry)?;

        tx.commit()?;
        Ok(())
    }

    fn create_auth(&mut self, auth_entry: &mut AuthEntry) -> Result<()> {
        debug!("Creating auth for user: {}", auth_entry.name);

        let tx = self.conn.transaction()?;

        tx.execute(
            "INSERT INTO auth (name, password, last_login) VALUES (?, ?, ?)",
            params![auth_entry.name, auth_entry.password, auth_entry.last_login],
        )?;

        // Get the auto-generated ID
        auth_entry.id = tx.last_insert_rowid() as u64;

        Self::write_privileges(&tx, auth_entry)?;

        tx.commit()?;
        Ok(())
    }

    fn delete_auth(&mut self, name: &str) -> Result<bool> {
        debug!("Deleting auth for user: {}", name);

        let changes = self
            .conn
            .execute("DELETE FROM auth WHERE name = ?", params![name])?;

        // Privileges are deleted automatically by ON DELETE CASCADE
        Ok(changes > 0)
    }

    fn list_names(&mut self) -> Result<Vec<String>> {
        debug!("Listing all usernames");

        let mut stmt = self
            .conn
            .prepare("SELECT name FROM auth ORDER BY name DESC")?;

        let names = stmt
            .query_map([], |row| row.get(0))?
            .collect::<std::result::Result<Vec<String>, _>>()?;

        Ok(names)
    }

    fn reload(&self) -> Result<()> {
        // No-op for SQLite (always fresh from disk)
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_create_and_get_auth() {
        let temp_dir = TempDir::new().unwrap();
        let mut db = AuthDatabaseSqlite::new(temp_dir.path()).unwrap();

        let mut auth = AuthEntry {
            id: 0,
            name: "testuser".to_string(),
            password: "hashed_password".to_string(),
            privileges: vec!["interact".to_string(), "shout".to_string()],
            last_login: 1234567890,
        };

        // Create user
        db.create_auth(&mut auth).unwrap();
        assert!(auth.id > 0);

        // Get user back
        let retrieved = db.get_auth("testuser").unwrap();
        assert_eq!(retrieved.name, "testuser");
        assert_eq!(retrieved.password, "hashed_password");
        assert_eq!(retrieved.privileges.len(), 2);
        assert!(retrieved.privileges.contains(&"interact".to_string()));
        assert_eq!(retrieved.last_login, 1234567890);
    }

    #[test]
    fn test_save_auth() {
        let temp_dir = TempDir::new().unwrap();
        let mut db = AuthDatabaseSqlite::new(temp_dir.path()).unwrap();

        let mut auth = AuthEntry {
            id: 0,
            name: "testuser".to_string(),
            password: "pass1".to_string(),
            privileges: vec!["interact".to_string()],
            last_login: 0,
        };

        db.create_auth(&mut auth).unwrap();

        // Modify and save
        auth.password = "new_pass".to_string();
        auth.privileges.push("fly".to_string());
        auth.last_login = 9999;

        db.save_auth(&auth).unwrap();

        // Verify changes
        let retrieved = db.get_auth("testuser").unwrap();
        assert_eq!(retrieved.password, "new_pass");
        assert_eq!(retrieved.privileges.len(), 2);
        assert_eq!(retrieved.last_login, 9999);
    }

    #[test]
    fn test_delete_auth() {
        let temp_dir = TempDir::new().unwrap();
        let mut db = AuthDatabaseSqlite::new(temp_dir.path()).unwrap();

        let mut auth = AuthEntry {
            id: 0,
            name: "testuser".to_string(),
            password: "pass".to_string(),
            privileges: vec![],
            last_login: 0,
        };

        db.create_auth(&mut auth).unwrap();

        // Delete user
        let deleted = db.delete_auth("testuser").unwrap();
        assert!(deleted);

        // Verify user is gone
        let result = db.get_auth("testuser");
        assert!(matches!(result, Err(AuthDbError::UserNotFound(_))));
    }

    #[test]
    fn test_list_names() {
        let temp_dir = TempDir::new().unwrap();
        let mut db = AuthDatabaseSqlite::new(temp_dir.path()).unwrap();

        // Create multiple users
        for name in &["user_a", "user_b", "user_c"] {
            let mut auth = AuthEntry {
                id: 0,
                name: name.to_string(),
                password: "pass".to_string(),
                privileges: vec![],
                last_login: 0,
            };
            db.create_auth(&mut auth).unwrap();
        }

        let names = db.list_names().unwrap();
        assert_eq!(names.len(), 3);
        assert!(names.contains(&"user_a".to_string()));
        assert!(names.contains(&"user_b".to_string()));
        assert!(names.contains(&"user_c".to_string()));
    }
}
