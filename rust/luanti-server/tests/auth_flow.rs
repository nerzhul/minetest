//! End-to-end integration test for the auth + media handshake.
//!
//! Drives the `CommandHandler` as if a real C++ Luanti client were
//! connecting:
//!
//! 1. `TOSERVER_INIT` -> expect `TOCLIENT_HELLO`
//! 2. `TOSERVER_FIRST_SRP` (register) -> expect `TOCLIENT_AUTH_ACCEPT`
//! 3. `TOSERVER_INIT2` -> expect a stream of init-data packets
//!    (ITEMDEF, NODEDEF, ANNOUNCE_MEDIA, TIME_OF_DAY, CSM, MOVEMENT)
//! 4. `TOSERVER_REQUEST_MEDIA` -> expect a single empty media bunch
//! 5. `TOSERVER_HAVE_MEDIA` -> no response
//! 6. `TOSERVER_CLIENT_READY` -> session transitions to Ingame

use std::net::SocketAddr;
use std::sync::Arc;

use command_handler::{CommandHandler, CommandPacket};
use luanti_auth_db::sqlite::AuthDatabaseSqlite;
use luanti_auth_db::AuthDatabase;
use luanti_network::{
    auth, wire::WireReader, AuthMechanism, ToClientCommand, ToServerCommand,
    ToServerConnectionState,
};
use luanti_server::command_handler;
use tempfile::TempDir;

use std::net::SocketAddrV4;
use std::str::FromStr;

/// Build an "as if received" command packet from the server's
/// perspective. The data is the body of the command (the `u16` opcode
/// is prepended automatically).
fn cmd(op: ToServerCommand, data: Vec<u8>) -> CommandPacket {
    let mut body = Vec::with_capacity(2 + data.len());
    body.extend_from_slice(&(op as u16).to_be_bytes());
    body.extend_from_slice(&data);
    CommandPacket::parse(&body, 42).unwrap()
}

/// Extract the `ToClientCommand` opcode from a server-to-client packet
/// payload (the `u16` at the front).
fn op_of(payload: &[u8]) -> ToClientCommand {
    let mut r = WireReader::new(payload);
    let code = r.read_u16().unwrap();
    ToClientCommand::from_u16(code).expect("unknown TOCLIENT opcode")
}

/// Drive the whole handshake and return the final session state and
/// the list of init-data responses (in order).
fn run_handshake() -> (CommandHandler, Vec<Vec<u8>>) {
    let tmp = TempDir::new().unwrap();
    let auth_db = AuthDatabaseSqlite::new(tmp.path()).unwrap();
    let mut handler = CommandHandler::new(37, 43, Box::new(auth_db));

    let peer: SocketAddr = SocketAddrV4::from_str("127.0.0.1:12345").unwrap().into();

    // We don't have direct access to a Session here; build one.
    // Session is created in main.rs via SessionManager; for the test
    // we'll construct one directly.
    use luanti_network::Session;
    let mut session = Session::new(42, peer);

    // --- Step 1: TOSERVER_INIT ---------------------------------------------
    let mut init_data = vec![
        29u8, // serialization_version
    ];
    init_data.extend_from_slice(&0u16.to_be_bytes()); // compression
    init_data.extend_from_slice(&37u16.to_be_bytes()); // min_proto
    init_data.extend_from_slice(&43u16.to_be_bytes()); // max_proto
    let name = b"alice";
    init_data.extend_from_slice(&(name.len() as u16).to_be_bytes());
    init_data.extend_from_slice(name);
    let init = cmd(ToServerCommand::Init, init_data);

    let responses = handler.handle_command(&mut session, &init, peer).unwrap();
    assert_eq!(responses.len(), 1, "INIT must produce exactly one response");
    let hello = &responses[0];
    assert_eq!(op_of(hello), ToClientCommand::Hello);
    assert_eq!(session.connection_state, ToServerConnectionState::Startup);
    assert_eq!(session.player_name.as_deref(), Some("alice"));

    // --- Step 2: TOSERVER_FIRST_SRP -----------------------------------------
    // Generate a valid salt + verifier for the user "alice" / "hunter2".
    let encoded = auth::get_encoded_srp_verifier("alice", "hunter2").unwrap();
    let (verifier, salt) = {
        let mut v = Vec::new();
        let mut s = Vec::new();
        assert!(auth::decode_srp_verifier_and_salt(
            &encoded, &mut v, &mut s
        ));
        (v, s)
    };
    let mut first_srp_data = Vec::new();
    first_srp_data.extend_from_slice(&(salt.len() as u16).to_be_bytes());
    first_srp_data.extend_from_slice(&salt);
    first_srp_data.extend_from_slice(&(verifier.len() as u16).to_be_bytes());
    first_srp_data.extend_from_slice(&verifier);
    first_srp_data.push(0); // is_empty = 0
    let first_srp = cmd(ToServerCommand::FirstSrp, first_srp_data);
    let responses = handler
        .handle_command(&mut session, &first_srp, peer)
        .unwrap();
    assert_eq!(responses.len(), 1, "FIRST_SRP must produce AUTH_ACCEPT");
    assert_eq!(op_of(&responses[0]), ToClientCommand::AuthAccept);

    // Player should now be in the auth DB.
    // (Re-open the DB to verify since handler owns the original connection.)
    let mut verify_db = AuthDatabaseSqlite::new(tmp.path()).unwrap();
    let entry = verify_db.get_auth("alice").expect("player should be in DB");
    assert_eq!(entry.password, encoded);

    // --- Step 3: TOSERVER_INIT2 ---------------------------------------------
    let init2 = cmd(ToServerCommand::Init2, Vec::new());
    let init_responses = handler
        .handle_command(&mut session, &init2, peer)
        .unwrap();
    assert!(session.media_loading, "session should be in media-loading phase");

    // We expect: ITEMDEF, NODEDEF, ANNOUNCE_MEDIA, TIME_OF_DAY,
    // CSM_RESTRICTION_FLAGS, MOVEMENT
    let opcodes: Vec<ToClientCommand> = init_responses.iter().map(|r| op_of(r)).collect();
    assert!(opcodes.contains(&ToClientCommand::ItemDef), "missing ItemDef: {:?}", opcodes);
    assert!(opcodes.contains(&ToClientCommand::NodeDef), "missing NodeDef: {:?}", opcodes);
    assert!(opcodes.contains(&ToClientCommand::AnnounceMedia), "missing AnnounceMedia: {:?}", opcodes);
    assert!(opcodes.contains(&ToClientCommand::TimeOfDay), "missing TimeOfDay: {:?}", opcodes);
    assert!(opcodes.contains(&ToClientCommand::CsmRestrictionFlags), "missing CSM: {:?}", opcodes);
    assert!(opcodes.contains(&ToClientCommand::Movement), "missing Movement: {:?}", opcodes);

    // --- Step 4: TOSERVER_REQUEST_MEDIA -------------------------------------
    // (With no media files served, the response is a single empty bunch.)
    let mut req_data = Vec::new();
    req_data.extend_from_slice(&0u16.to_be_bytes()); // 0 files requested
    let req = cmd(ToServerCommand::RequestMedia, req_data);
    let responses = handler.handle_command(&mut session, &req, peer).unwrap();
    assert_eq!(responses.len(), 1, "REQUEST_MEDIA should return one (empty) bunch");
    let media_pkt = &responses[0];
    assert_eq!(op_of(media_pkt), ToClientCommand::Media);
    // total_bunches=1, bunch_i=0, num_files=0
    let mut r = WireReader::new(&media_pkt[2..]);
    assert_eq!(r.read_u16().unwrap(), 1, "total_bunches");
    assert_eq!(r.read_u16().unwrap(), 0, "bunch_index");
    assert_eq!(r.read_u32().unwrap(), 0, "num_files");

    // --- Step 5: TOSERVER_HAVE_MEDIA ----------------------------------------
    let have_data = vec![0u8]; // 0 tokens
    let have = cmd(ToServerCommand::HaveMedia, have_data);
    let responses = handler.handle_command(&mut session, &have, peer).unwrap();
    assert!(responses.is_empty(), "HAVE_MEDIA has no response");

    // --- Step 6: TOSERVER_CLIENT_READY --------------------------------------
    let mut ready_data = vec![5u8, 9, 0, 0]; // major=5, minor=9, patch=0, reserved=0
    ready_data.extend_from_slice(&1u16.to_be_bytes()); // "fr" length = 1
    ready_data.extend_from_slice(b"5.9.0");
    let ready = cmd(ToServerCommand::ClientReady, ready_data);
    let responses = handler.handle_command(&mut session, &ready, peer).unwrap();
    assert!(responses.is_empty(), "CLIENT_READY has no response");
    assert!(session.client_ready);
    assert_eq!(session.connection_state, ToServerConnectionState::Ingame);

    (handler, init_responses)
}

#[test]
fn full_handshake() {
    let (_handler, _init_responses) = run_handshake();
}

#[test]
fn init_rejects_invalid_name() {
    let tmp = TempDir::new().unwrap();
    let auth_db = AuthDatabaseSqlite::new(tmp.path()).unwrap();
    let mut handler = CommandHandler::new(37, 43, Box::new(auth_db));

    let peer: SocketAddr = SocketAddrV4::from_str("127.0.0.1:12346").unwrap().into();
    use luanti_network::Session;
    let mut session = Session::new(7, peer);

    // A name with a forbidden character (space)
    let mut init_data = vec![29u8];
    init_data.extend_from_slice(&0u16.to_be_bytes());
    init_data.extend_from_slice(&37u16.to_be_bytes());
    init_data.extend_from_slice(&43u16.to_be_bytes());
    let name = b"bad name";
    init_data.extend_from_slice(&(name.len() as u16).to_be_bytes());
    init_data.extend_from_slice(name);
    let init = cmd(ToServerCommand::Init, init_data);

    let responses = handler.handle_command(&mut session, &init, peer).unwrap();
    assert_eq!(responses.len(), 1);
    assert_eq!(op_of(&responses[0]), ToClientCommand::AccessDenied);
}

#[test]
fn init_rejects_wrong_version() {
    let tmp = TempDir::new().unwrap();
    let auth_db = AuthDatabaseSqlite::new(tmp.path()).unwrap();
    let mut handler = CommandHandler::new(37, 43, Box::new(auth_db));

    let peer: SocketAddr = SocketAddrV4::from_str("127.0.0.1:12347").unwrap().into();
    use luanti_network::Session;
    let mut session = Session::new(8, peer);

    // Too-old protocol
    let mut init_data = vec![29u8];
    init_data.extend_from_slice(&0u16.to_be_bytes());
    init_data.extend_from_slice(&1u16.to_be_bytes());
    init_data.extend_from_slice(&5u16.to_be_bytes());
    let name = b"bob";
    init_data.extend_from_slice(&(name.len() as u16).to_be_bytes());
    init_data.extend_from_slice(name);
    let init = cmd(ToServerCommand::Init, init_data);

    let responses = handler.handle_command(&mut session, &init, peer).unwrap();
    assert_eq!(responses.len(), 1);
    assert_eq!(op_of(&responses[0]), ToClientCommand::AccessDenied);
}

#[test]
fn media_commands_rejected_before_init2() {
    let tmp = TempDir::new().unwrap();
    let auth_db = AuthDatabaseSqlite::new(tmp.path()).unwrap();
    let mut handler = CommandHandler::new(37, 43, Box::new(auth_db));

    let peer: SocketAddr = SocketAddrV4::from_str("127.0.0.1:12348").unwrap().into();
    use luanti_network::Session;
    let mut session = Session::new(9, peer);

    // First do a valid INIT to get to Startup
    let mut init_data = vec![29u8];
    init_data.extend_from_slice(&0u16.to_be_bytes());
    init_data.extend_from_slice(&37u16.to_be_bytes());
    init_data.extend_from_slice(&43u16.to_be_bytes());
    let name = b"carol";
    init_data.extend_from_slice(&(name.len() as u16).to_be_bytes());
    init_data.extend_from_slice(name);
    let init = cmd(ToServerCommand::Init, init_data);
    let _ = handler.handle_command(&mut session, &init, peer).unwrap();

    // Now REQUEST_MEDIA should be rejected (no response, not in media_loading phase)
    let req = cmd(ToServerCommand::RequestMedia, vec![0, 0]); // 0 files
    let responses = handler.handle_command(&mut session, &req, peer).unwrap();
    assert!(
        responses.is_empty(),
        "REQUEST_MEDIA before INIT2 should produce no response"
    );
}

#[test]
fn srp_bytes_a_rejects_disallowed_mech() {
    let tmp = TempDir::new().unwrap();
    let auth_db = AuthDatabaseSqlite::new(tmp.path()).unwrap();
    let mut handler = CommandHandler::new(37, 43, Box::new(auth_db));

    let peer: SocketAddr = SocketAddrV4::from_str("127.0.0.1:12349").unwrap().into();
    use luanti_network::Session;
    let mut session = Session::new(10, peer);

    // INIT first
    let mut init_data = vec![29u8];
    init_data.extend_from_slice(&0u16.to_be_bytes());
    init_data.extend_from_slice(&37u16.to_be_bytes());
    init_data.extend_from_slice(&43u16.to_be_bytes());
    let name = b"dave";
    init_data.extend_from_slice(&(name.len() as u16).to_be_bytes());
    init_data.extend_from_slice(name);
    let init = cmd(ToServerCommand::Init, init_data);
    let _ = handler.handle_command(&mut session, &init, peer).unwrap();

    // After INIT, the server only allows FIRST_SRP (new user, no record).
    // Send SRP_BYTES_A with based_on=0 (legacy) - should be rejected.
    let mut a_data = Vec::new();
    let a_bytes = vec![0u8; 256];
    a_data.extend_from_slice(&(a_bytes.len() as u16).to_be_bytes());
    a_data.extend_from_slice(&a_bytes);
    a_data.push(0); // based_on=0 (legacy)
    let a = cmd(ToServerCommand::SrpBytesA, a_data);
    let responses = handler.handle_command(&mut session, &a, peer).unwrap();
    assert_eq!(responses.len(), 1);
    assert_eq!(op_of(&responses[0]), ToClientCommand::AccessDenied);
}

// Unused, but keeps the linter happy
#[allow(dead_code)]
fn _unused() {
    let _ = Arc::new(());
    let _: AuthMechanism = AuthMechanism::FirstSrp;
}
