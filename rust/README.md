# Luanti Rust Server

Implémentation en Rust de la couche session et de la couche applicative (opcodes) du protocole réseau de Luanti (anciennement Minetest).

## Description

Ce projet implémente le protocole MTP (Minetest Protocol) en Rust, avec :

### Couche Session
- Gestion des sessions UDP
- Support des différents types de paquets (Control, Original, Split, Reliable)
- Gestion des numéros de séquence et des ACKs
- Réassemblage des paquets fragmentés
- Gestion du timeout des sessions

### Couche Applicative (Opcodes)
- Gestion des commandes du protocole (ToServerCommand / ToClientCommand)
- Handler de commandes avec machine d'états
- Support des commandes principales :
  - **TOSERVER_INIT** - Initialisation client
  - **TOSERVER_INIT2** - Confirmation d'authentification
  - **TOSERVER_CHAT_MESSAGE** - Messages de chat
  - **TOSERVER_PLAYERPOS** - Position du joueur
  - **TOSERVER_CLIENT_READY** - Client prêt
- Négociation de version du protocole
- Génération de réponses TOCLIENT (HELLO, AUTH_ACCEPT, CHAT_MESSAGE, etc.)

## Architecture

```
src/
├── main.rs              - Serveur UDP principal et routage
├── protocol.rs          - Définitions du protocole MTP (types de paquets, constantes)
├── session.rs           - Gestion des sessions par pair
├── packet.rs            - Structures de paquets et utilitaires
├── opcodes.rs           - Enumérations des opcodes et états de connexion
└── command_handler.rs   - Gestionnaire de commandes applicatives
```

## Structure du Protocole

### En-tête de base (7 octets)
```
[0..4] u32 protocol_id (0x4f457403)
[4..6] u16 sender_peer_id
[6]    u8  channel
```

### Types de paquets

1. **CONTROL (0)** - Paquets de contrôle du protocole
   - ACK (0) - Acquittement
   - SET_PEER_ID (1) - Attribution d'ID de pair
   - PING (2) - Ping
   - DISCO (3) - Déconnexion

2. **ORIGINAL (1)** - Paquets simples sans contrôle d'erreur

3. **SPLIT (2)** - Paquets fragmentés pour les grandes données

4. **RELIABLE (3)** - Paquets fiables avec ACK obligatoire

## Compilation et Exécution

```bash
cd rust
cargo build --release
cargo run --release
```

Le serveur écoute par défaut sur le port UDP 30000.

## Dépendances

- `tokio` - Runtime asynchrone pour Rust
- `bytes` - Manipulation efficace des buffers
- `log` / `env_logger` - Logging
- `anyhow` / `thiserror` - Gestion des erreurs

## Configuration des logs

Pour activer les logs de debug :

```bash
RUST_LOG=debug cargo run
```

## Compatibilité

Ce serveur implémente la couche session de base compatible avec le protocole réseau de Luanti tel que défini dans `src/network/mtp/`.

## Licence

Ce projet suit la même licence que Luanti (LGPL-2.1-or-later).
