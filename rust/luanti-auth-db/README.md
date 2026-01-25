# Luanti Auth Database

Bibliothèque Rust pour la base de données d'authentification de Luanti (Minetest).

## Fonctionnalités

- Support SQLite3 (compatible avec `AuthDatabaseSQLite3` C++)
- Support PostgreSQL (compatible avec `AuthDatabasePostgreSQL` C++)
- Interface trait commune `AuthDatabase`
- Schéma de base de données 100% compatible avec l'implémentation C++

## Installation

```toml
[dependencies]
luanti-auth-db = { path = "../luanti-auth-db" }

# Pour activer seulement SQLite
luanti-auth-db = { path = "../luanti-auth-db", default-features = false, features = ["sqlite"] }

# Pour activer seulement PostgreSQL
luanti-auth-db = { path = "../luanti-auth-db", default-features = false, features = ["postgres"] }
```

## Utilisation

### SQLite3

```rust
use luanti_auth_db::{AuthDatabase, AuthEntry, sqlite::AuthDatabaseSqlite};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db = AuthDatabaseSqlite::new("./world")?;
    
    // Créer un nouvel utilisateur
    let mut auth_entry = AuthEntry {
        id: 0,
        name: "player1".to_string(),
        password: "hashed_password_here".to_string(),
        privileges: vec!["interact".to_string(), "shout".to_string()],
        last_login: 0,
    };
    
    db.create_auth(&mut auth_entry)?;
    println!("Created user with ID: {}", auth_entry.id);
    
    // Récupérer un utilisateur
    let auth = db.get_auth("player1")?;
    println!("User: {}, Privileges: {:?}", auth.name, auth.privileges);
    
    // Modifier un utilisateur
    let mut auth = db.get_auth("player1")?;
    auth.privileges.push("fly".to_string());
    auth.last_login = chrono::Utc::now().timestamp();
    db.save_auth(&auth)?;
    
    // Lister tous les utilisateurs
    let users = db.list_names()?;
    println!("Users: {:?}", users);
    
    // Supprimer un utilisateur
    db.delete_auth("player1")?;
    
    Ok(())
}
```

### PostgreSQL

```rust
use luanti_auth_db::{AuthDatabase, AuthEntry, postgres::AuthDatabasePostgres};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db = AuthDatabasePostgres::new(
        "host=localhost user=postgres password=pass dbname=luanti"
    ).await?;
    
    // Utilisation asynchrone
    let mut auth_entry = AuthEntry {
        id: 0,
        name: "player1".to_string(),
        password: "hashed_password".to_string(),
        privileges: vec!["interact".to_string()],
        last_login: 0,
    };
    
    db.create_auth_async(&mut auth_entry).await?;
    
    let auth = db.get_auth_async("player1").await?;
    println!("User: {}", auth.name);
    
    Ok(())
}
```

## Structure de la base de données

### Table `auth`

| Colonne      | Type    | Description                   |
|--------------|---------|-------------------------------|
| id           | INTEGER | ID auto-incrémenté (clé primaire) |
| name         | TEXT    | Nom d'utilisateur (unique)    |
| password     | TEXT    | Hash du mot de passe          |
| last_login   | INTEGER | Timestamp du dernier login    |

### Table `user_privileges`

| Colonne    | Type    | Description                     |
|------------|---------|--------------------------------|
| id         | INTEGER | ID utilisateur (clé étrangère) |
| privilege  | TEXT    | Nom du privilège               |

Clé primaire: `(id, privilege)`  
Foreign key: `id` → `auth(id)` ON DELETE CASCADE

## Compatibilité

Cette bibliothèque est 100% compatible avec les bases de données créées par Luanti C++. Vous pouvez:
- Utiliser une base de données existante créée par Luanti C++
- Créer une base de données avec cette bibliothèque et l'utiliser avec Luanti C++
- Basculer entre les deux implémentations sans migration

## Tests

```bash
# Tests SQLite (ne nécessitent pas de serveur externe)
cargo test --features sqlite

# Tests PostgreSQL (nécessitent un serveur PostgreSQL en cours d'exécution)
cargo test --features postgres -- --ignored
```

## Licence

LGPL-2.1-or-later (compatible avec Luanti)
