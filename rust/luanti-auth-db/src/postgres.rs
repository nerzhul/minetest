//! PostgreSQL authentication database implementation
//!
//! Compatible with the C++ AuthDatabasePostgreSQL class.

use crate::{AuthDatabase, AuthDbError, AuthEntry, Result};
use log::{debug, error};
use tokio_postgres::{Client, Config, NoTls};

/// PostgreSQL authentication database
///
/// Manages authentication in a PostgreSQL database with tables:
/// - `auth`: user accounts
/// - `user_privileges`: user privileges
///
/// Schema is compatible with the C++ implementation.
pub struct AuthDatabasePostgres {
    client: Client,
}

impl AuthDatabasePostgres {
    /// Create or open the authentication database
    ///
    /// # Arguments
    /// * `connect_string` - PostgreSQL connection string (e.g., "host=localhost user=postgres dbname=luanti")
    ///
    /// # Example
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use luanti_auth_db::postgres::AuthDatabasePostgres;
    ///
    /// let db = AuthDatabasePostgres::new("host=localhost user=postgres password=pass dbname=luanti").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn new(connect_string: &str) -> Result<Self> {
        debug!("Connecting to PostgreSQL: {}", connect_string);

        let config: Config = connect_string.parse().map_err(|e| {
            AuthDbError::ConnectionError(format!("Invalid connection string: {}", e))
        })?;

        let (client, connection) = config.connect(NoTls).await.map_err(|e| {
            error!("Failed to connect to PostgreSQL: {}", e);
            e
        })?;

        // Spawn connection handler
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                error!("PostgreSQL connection error: {}", e);
            }
        });

        let db = AuthDatabasePostgres { client };
        db.create_database().await?;
        db.init_statements().await?;
        Ok(db)
    }

    /// Create database tables if they don't exist
    async fn create_database(&self) -> Result<()> {
        // Create auth table
        self.client
            .execute(
                "CREATE TABLE IF NOT EXISTS auth (
                    id SERIAL,
                    name TEXT UNIQUE,
                    password TEXT,
                    last_login INT NOT NULL DEFAULT 0,
                    PRIMARY KEY (id)
                )",
                &[],
            )
            .await?;

        // Create user_privileges table
        self.client
            .execute(
                "CREATE TABLE IF NOT EXISTS user_privileges (
                    id INT,
                    privilege TEXT,
                    PRIMARY KEY (id, privilege),
                    CONSTRAINT fk_id FOREIGN KEY (id) REFERENCES auth (id) ON DELETE CASCADE
                )",
                &[],
            )
            .await?;

        debug!("Auth database tables created/verified");
        Ok(())
    }

    /// Initialize prepared statements (placeholder for future optimization)
    async fn init_statements(&self) -> Result<()> {
        // PostgreSQL prepared statements would be set up here
        // For now, we'll use direct queries
        Ok(())
    }

    /// Write privileges for an auth entry
    async fn write_privileges(&self, auth_entry: &AuthEntry) -> Result<()> {
        // Delete existing privileges
        self.client
            .execute(
                "DELETE FROM user_privileges WHERE id = $1",
                &[&(auth_entry.id as i32)],
            )
            .await?;

        // Insert new privileges
        for privilege in &auth_entry.privileges {
            self.client
                .execute(
                    "INSERT INTO user_privileges (id, privilege) VALUES ($1, $2)",
                    &[&(auth_entry.id as i32), privilege],
                )
                .await?;
        }

        Ok(())
    }
}

impl AuthDatabasePostgres {
    /// Get authentication entry by username (async version)
    pub async fn get_auth_async(&mut self, name: &str) -> Result<AuthEntry> {
        debug!("Getting auth for user: {}", name);

        let row = self
            .client
            .query_opt(
                "SELECT id, name, password, last_login FROM auth WHERE name = $1",
                &[&name],
            )
            .await?;

        let row = row.ok_or_else(|| AuthDbError::UserNotFound(name.to_string()))?;

        let id: i32 = row.get(0);
        let auth_name: String = row.get(1);
        let password: String = row.get(2);
        let last_login: i32 = row.get(3);

        // Read privileges
        let priv_rows = self
            .client
            .query(
                "SELECT privilege FROM user_privileges WHERE id = $1",
                &[&id],
            )
            .await?;

        let privileges: Vec<String> = priv_rows.iter().map(|row| row.get(0)).collect();

        Ok(AuthEntry {
            id: id as u64,
            name: auth_name,
            password,
            privileges,
            last_login: last_login as i64,
        })
    }

    /// Save (update) an existing authentication entry (async version)
    pub async fn save_auth_async(&mut self, auth_entry: &AuthEntry) -> Result<()> {
        debug!("Saving auth for user: {}", auth_entry.name);

        // Begin transaction
        let transaction = self.client.transaction().await?;

        transaction
            .execute(
                "UPDATE auth SET name = $1, password = $2, last_login = $3 WHERE id = $4",
                &[
                    &auth_entry.name,
                    &auth_entry.password,
                    &(auth_entry.last_login as i32),
                    &(auth_entry.id as i32),
                ],
            )
            .await?;

        // Delete old privileges
        transaction
            .execute(
                "DELETE FROM user_privileges WHERE id = $1",
                &[&(auth_entry.id as i32)],
            )
            .await?;

        // Insert new privileges
        for privilege in &auth_entry.privileges {
            transaction
                .execute(
                    "INSERT INTO user_privileges (id, privilege) VALUES ($1, $2)",
                    &[&(auth_entry.id as i32), privilege],
                )
                .await?;
        }

        transaction.commit().await?;
        Ok(())
    }

    /// Create a new authentication entry (async version)
    pub async fn create_auth_async(&mut self, auth_entry: &mut AuthEntry) -> Result<()> {
        debug!("Creating auth for user: {}", auth_entry.name);

        // Begin transaction
        let transaction = self.client.transaction().await?;

        let row = transaction
            .query_one(
                "INSERT INTO auth (name, password, last_login) VALUES ($1, $2, $3) RETURNING id",
                &[
                    &auth_entry.name,
                    &auth_entry.password,
                    &(auth_entry.last_login as i32),
                ],
            )
            .await?;

        let id: i32 = row.get(0);
        auth_entry.id = id as u64;

        // Insert privileges
        for privilege in &auth_entry.privileges {
            transaction
                .execute(
                    "INSERT INTO user_privileges (id, privilege) VALUES ($1, $2)",
                    &[&id, privilege],
                )
                .await?;
        }

        transaction.commit().await?;
        Ok(())
    }

    /// Delete authentication entry by username (async version)
    pub async fn delete_auth_async(&mut self, name: &str) -> Result<bool> {
        debug!("Deleting auth for user: {}", name);

        let rows_affected = self
            .client
            .execute("DELETE FROM auth WHERE name = $1", &[&name])
            .await?;

        // Privileges are deleted automatically by ON DELETE CASCADE
        Ok(rows_affected > 0)
    }

    /// List all usernames (async version)
    pub async fn list_names_async(&mut self) -> Result<Vec<String>> {
        debug!("Listing all usernames");

        let rows = self
            .client
            .query("SELECT name FROM auth ORDER BY name DESC", &[])
            .await?;

        let names: Vec<String> = rows.iter().map(|row| row.get(0)).collect();

        Ok(names)
    }

    /// Reload database - no-op for PostgreSQL (async version)
    pub async fn reload_async(&self) -> Result<()> {
        // No-op for PostgreSQL
        Ok(())
    }
}

// Synchronous wrapper using tokio runtime
// Note: In a real async application, you should use the async methods directly
impl AuthDatabase for AuthDatabasePostgres {
    fn get_auth(&mut self, name: &str) -> Result<AuthEntry> {
        tokio::runtime::Handle::current().block_on(self.get_auth_async(name))
    }

    fn save_auth(&mut self, auth_entry: &AuthEntry) -> Result<()> {
        tokio::runtime::Handle::current().block_on(self.save_auth_async(auth_entry))
    }

    fn create_auth(&mut self, auth_entry: &mut AuthEntry) -> Result<()> {
        tokio::runtime::Handle::current().block_on(self.create_auth_async(auth_entry))
    }

    fn delete_auth(&mut self, name: &str) -> Result<bool> {
        tokio::runtime::Handle::current().block_on(self.delete_auth_async(name))
    }

    fn list_names(&mut self) -> Result<Vec<String>> {
        tokio::runtime::Handle::current().block_on(self.list_names_async())
    }

    fn reload(&self) -> Result<()> {
        tokio::runtime::Handle::current().block_on(self.reload_async())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: These tests require a running PostgreSQL instance
    // They are marked as ignored by default

    #[tokio::test]
    #[ignore]
    async fn test_create_and_get_auth() {
        let mut db = AuthDatabasePostgres::new("host=localhost user=postgres dbname=luanti_test")
            .await
            .unwrap();

        let mut auth = AuthEntry {
            id: 0,
            name: "testuser".to_string(),
            password: "hashed_password".to_string(),
            privileges: vec!["interact".to_string(), "shout".to_string()],
            last_login: 1234567890,
        };

        // Create user
        db.create_auth_async(&mut auth).await.unwrap();
        assert!(auth.id > 0);

        // Get user back
        let retrieved = db.get_auth_async("testuser").await.unwrap();
        assert_eq!(retrieved.name, "testuser");
        assert_eq!(retrieved.password, "hashed_password");
        assert_eq!(retrieved.privileges.len(), 2);

        // Cleanup
        db.delete_auth_async("testuser").await.unwrap();
    }

    #[tokio::test]
    #[ignore]
    async fn test_list_names() {
        let mut db = AuthDatabasePostgres::new("host=localhost user=postgres dbname=luanti_test")
            .await
            .unwrap();

        // Create test users
        for name in &["user_a", "user_b", "user_c"] {
            let mut auth = AuthEntry {
                id: 0,
                name: name.to_string(),
                password: "pass".to_string(),
                privileges: vec![],
                last_login: 0,
            };
            db.create_auth_async(&mut auth).await.unwrap();
        }

        let names = db.list_names_async().await.unwrap();
        assert!(names.len() >= 3);

        // Cleanup
        for name in &["user_a", "user_b", "user_c"] {
            db.delete_auth_async(name).await.unwrap();
        }
    }
}
