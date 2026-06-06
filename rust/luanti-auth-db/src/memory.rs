//! In-memory authentication database implementation
//!
//! Stores auth entries in a `HashMap` guarded by a `Mutex`. Useful for
//! tests, ephemeral servers, and cases where persistence is not required.
//!
//! Compatible with the C++ `AuthDatabase` interface used elsewhere.

use crate::{AuthDatabase, AuthDbError, AuthEntry, Result};
use log::debug;
use std::collections::HashMap;
use std::sync::Mutex;

/// In-memory authentication database
///
/// Entries live in process memory only and are lost when the server
/// stops. Safe to share between threads thanks to the internal `Mutex`.
pub struct AuthDatabaseMemory {
    entries: Mutex<HashMap<String, AuthEntry>>,
    next_id: Mutex<u64>,
}

impl AuthDatabaseMemory {
    /// Create a new, empty in-memory auth database.
    pub fn new() -> Self {
        debug!("Creating in-memory auth database");
        Self {
            entries: Mutex::new(HashMap::new()),
            next_id: Mutex::new(1),
        }
    }

    /// Number of users currently stored.
    pub fn len(&self) -> usize {
        self.entries.lock().expect("auth db mutex poisoned").len()
    }

    /// Whether the database is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for AuthDatabaseMemory {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthDatabase for AuthDatabaseMemory {
    fn get_auth(&mut self, name: &str) -> Result<AuthEntry> {
        debug!("Getting auth for user: {}", name);
        let entries = self.entries.lock().expect("auth db mutex poisoned");
        entries
            .get(name)
            .cloned()
            .ok_or_else(|| AuthDbError::UserNotFound(name.to_string()))
    }

    fn save_auth(&mut self, auth_entry: &AuthEntry) -> Result<()> {
        debug!("Saving auth for user: {}", auth_entry.name);
        let mut entries = self.entries.lock().expect("auth db mutex poisoned");
        if !entries.contains_key(&auth_entry.name) {
            return Err(AuthDbError::UserNotFound(auth_entry.name.clone()));
        }
        entries.insert(auth_entry.name.clone(), auth_entry.clone());
        Ok(())
    }

    fn create_auth(&mut self, auth_entry: &mut AuthEntry) -> Result<()> {
        debug!("Creating auth for user: {}", auth_entry.name);
        let mut entries = self.entries.lock().expect("auth db mutex poisoned");
        if entries.contains_key(&auth_entry.name) {
            return Err(AuthDbError::UserAlreadyExists(auth_entry.name.clone()));
        }
        let mut next_id = self.next_id.lock().expect("auth db mutex poisoned");
        auth_entry.id = *next_id;
        *next_id += 1;
        entries.insert(auth_entry.name.clone(), auth_entry.clone());
        Ok(())
    }

    fn delete_auth(&mut self, name: &str) -> Result<bool> {
        debug!("Deleting auth for user: {}", name);
        let mut entries = self.entries.lock().expect("auth db mutex poisoned");
        Ok(entries.remove(name).is_some())
    }

    fn list_names(&mut self) -> Result<Vec<String>> {
        let entries = self.entries.lock().expect("auth db mutex poisoned");
        let mut names: Vec<String> = entries.keys().cloned().collect();
        names.sort();
        Ok(names)
    }

    fn reload(&self) -> Result<()> {
        // No-op: in-memory state never goes stale.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AuthDatabase;

    fn make_entry(name: &str) -> AuthEntry {
        AuthEntry {
            id: 0,
            name: name.to_string(),
            password: "hash".to_string(),
            privileges: vec!["interact".to_string(), "shout".to_string()],
            last_login: 0,
        }
    }

    #[test]
    fn create_and_get() {
        let mut db = AuthDatabaseMemory::new();
        let mut entry = make_entry("alice");
        db.create_auth(&mut entry).unwrap();
        assert!(entry.id >= 1);

        let fetched = db.get_auth("alice").unwrap();
        assert_eq!(fetched.name, "alice");
        assert_eq!(fetched.password, "hash");
        assert_eq!(fetched.privileges.len(), 2);
    }

    #[test]
    fn duplicate_create_errors() {
        let mut db = AuthDatabaseMemory::new();
        let mut entry = make_entry("bob");
        db.create_auth(&mut entry).unwrap();
        let mut dup = make_entry("bob");
        assert!(matches!(
            db.create_auth(&mut dup),
            Err(AuthDbError::UserAlreadyExists(_))
        ));
    }

    #[test]
    fn get_missing_errors() {
        let mut db = AuthDatabaseMemory::new();
        assert!(matches!(
            db.get_auth("ghost"),
            Err(AuthDbError::UserNotFound(_))
        ));
    }

    #[test]
    fn save_requires_existing() {
        let mut db = AuthDatabaseMemory::new();
        let entry = make_entry("carol");
        assert!(matches!(
            db.save_auth(&entry),
            Err(AuthDbError::UserNotFound(_))
        ));
    }

    #[test]
    fn save_updates_entry() {
        let mut db = AuthDatabaseMemory::new();
        let mut entry = make_entry("dave");
        db.create_auth(&mut entry).unwrap();

        let mut updated = db.get_auth("dave").unwrap();
        updated.password = "newhash".to_string();
        updated.privileges.clear();
        db.save_auth(&updated).unwrap();

        let fetched = db.get_auth("dave").unwrap();
        assert_eq!(fetched.password, "newhash");
        assert!(fetched.privileges.is_empty());
    }

    #[test]
    fn delete_returns_true_when_present() {
        let mut db = AuthDatabaseMemory::new();
        let mut entry = make_entry("erin");
        db.create_auth(&mut entry).unwrap();
        assert!(db.delete_auth("erin").unwrap());
        assert!(!db.delete_auth("erin").unwrap());
    }

    #[test]
    fn list_names_is_sorted() {
        let mut db = AuthDatabaseMemory::new();
        for name in ["zoe", "alice", "mike"] {
            let mut entry = make_entry(name);
            db.create_auth(&mut entry).unwrap();
        }
        let names = db.list_names().unwrap();
        assert_eq!(names, vec!["alice", "mike", "zoe"]);
    }

    #[test]
    fn ids_are_unique_and_monotonic() {
        let mut db = AuthDatabaseMemory::new();
        let mut a = make_entry("a");
        let mut b = make_entry("b");
        db.create_auth(&mut a).unwrap();
        db.create_auth(&mut b).unwrap();
        assert!(b.id > a.id);
    }
}
