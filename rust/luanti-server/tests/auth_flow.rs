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
use std::net::SocketAddrV4;
use std::str::FromStr;

use luanti_auth_db::sqlite::AuthDatabaseSqlite;
use luanti_auth_db::AuthDatabase;
use luanti_network::{
    auth, wire::WireReader, NetworkPacket, SessionPhase, ToClientCommand, ToServerCommand,
};
use luanti_server::command_handler::CommandHandler;
use tempfile::TempDir;

/// Build a `NetworkPacket` carrying the given ToServer opcode. The
/// caller is then expected to write the command payload bytes into the
/// returned packet via the `NetworkPacket::write_*` methods.
fn cmd(op: ToServerCommand) -> NetworkPacket {
    NetworkPacket::new(op as u16, 0)
}

/// Extract the `ToClientCommand` opcode from a server-to-client packet
/// payload (the `u16` at the front).
fn op_of(payload: &NetworkPacket) -> ToClientCommand {
    ToClientCommand::from_u16(payload.command()).expect("unknown TOCLIENT opcode")
}

#[test]
fn full_handshake() {
    let tmp = TempDir::new().unwrap();
    let auth_db = AuthDatabaseSqlite::new(tmp.path()).unwrap();
    let mut handler = CommandHandler::new(37, 43, Box::new(auth_db));

    let peer: SocketAddr = SocketAddrV4::from_str("127.0.0.1:12345").unwrap().into();
    use luanti_network::Session;
    let mut session = Session::new(42, peer);

    // --- Step 1: TOSERVER_INIT ---------------------------------------------
    let mut init = cmd(ToServerCommand::Init);
    init.write_u8(29); // serialization_version
    init.write_u16(0); // compression
    init.write_u16(37); // min_proto
    init.write_u16(43); // max_proto
    init.write_utf8("alice");

    let responses = handler.handle_command(&mut session, &init).unwrap();
    assert_eq!(responses.len(), 1, "INIT must produce exactly one response");
    let hello = &responses[0];
    assert_eq!(op_of(hello), ToClientCommand::Hello);
    // C++ CS_Created --CSE_Hello--> CS_HelloSent
    assert_eq!(session.phase, SessionPhase::HelloSent);
    assert_eq!(session.player_name.as_deref(), Some("alice"));

    // --- Step 2: TOSERVER_FIRST_SRP -----------------------------------------
    // Generate a valid salt + verifier for the user "alice" / "hunter2".
    let encoded = auth::get_encoded_srp_verifier("alice", "hunter2").unwrap();
    let (verifier, salt) = {
        let mut v = Vec::new();
        let mut s = Vec::new();
        assert!(auth::decode_srp_verifier_and_salt(&encoded, &mut v, &mut s));
        (v, s)
    };
    let mut first_srp = cmd(ToServerCommand::FirstSrp);
    first_srp.write_string(&salt);
    first_srp.write_string(&verifier);
    first_srp.write_u8(0); // is_empty = 0
    let responses = handler.handle_command(&mut session, &first_srp).unwrap();
    assert_eq!(responses.len(), 1, "FIRST_SRP must produce AUTH_ACCEPT");
    assert_eq!(op_of(&responses[0]), ToClientCommand::AuthAccept);

    // Player should now be in the auth DB.
    let mut verify_db = AuthDatabaseSqlite::new(tmp.path()).unwrap();
    let entry = verify_db.get_auth("alice").expect("player should be in DB");
    assert_eq!(entry.password, encoded);

    // --- Step 3: TOSERVER_INIT2 ---------------------------------------------
    let init2 = cmd(ToServerCommand::Init2);
    let init_responses = handler.handle_command(&mut session, &init2).unwrap();
    assert_eq!(
        session.phase,
        SessionPhase::DefinitionsSent,
        "session should be past media loading (C++ CS_DefinitionsSent)"
    );

    let opcodes: Vec<ToClientCommand> = init_responses.iter().map(|r| op_of(r)).collect();
    assert!(
        opcodes.contains(&ToClientCommand::ItemDef),
        "missing ItemDef: {:?}",
        opcodes
    );
    assert!(
        opcodes.contains(&ToClientCommand::NodeDef),
        "missing NodeDef: {:?}",
        opcodes
    );
    assert!(
        opcodes.contains(&ToClientCommand::AnnounceMedia),
        "missing AnnounceMedia: {:?}",
        opcodes
    );
    assert!(
        opcodes.contains(&ToClientCommand::TimeOfDay),
        "missing TimeOfDay: {:?}",
        opcodes
    );
    assert!(
        opcodes.contains(&ToClientCommand::CsmRestrictionFlags),
        "missing CSM: {:?}",
        opcodes
    );
    assert!(
        opcodes.contains(&ToClientCommand::Movement),
        "missing Movement: {:?}",
        opcodes
    );

    // --- Step 4: TOSERVER_REQUEST_MEDIA -------------------------------------
    let mut req = cmd(ToServerCommand::RequestMedia);
    req.write_u16(0); // 0 files requested
    let responses = handler.handle_command(&mut session, &req).unwrap();
    assert_eq!(
        responses.len(),
        1,
        "REQUEST_MEDIA should return one (empty) bunch"
    );
    let media_pkt = &responses[0];
    assert_eq!(op_of(media_pkt), ToClientCommand::Media);
    let mut r = WireReader::new(media_pkt.as_slice());
    assert_eq!(r.read_u16().unwrap(), 1, "total_bunches");
    assert_eq!(r.read_u16().unwrap(), 0, "bunch_index");
    assert_eq!(r.read_u32().unwrap(), 0, "num_files");

    // --- Step 5: TOSERVER_HAVE_MEDIA ----------------------------------------
    let mut have = cmd(ToServerCommand::HaveMedia);
    have.write_u8(0); // 0 tokens
    let responses = handler.handle_command(&mut session, &have).unwrap();
    assert!(responses.is_empty(), "HAVE_MEDIA has no response");

    // --- Step 6: TOSERVER_CLIENT_READY --------------------------------------
    let mut ready = cmd(ToServerCommand::ClientReady);
    ready.write_u8(5); // major
    ready.write_u8(9); // minor
    ready.write_u8(0); // patch
    ready.write_u8(0); // reserved
    ready.write_utf8("5.9.0");
    let responses = handler.handle_command(&mut session, &ready).unwrap();
    assert!(responses.is_empty(), "CLIENT_READY has no response");
    assert_eq!(session.phase, SessionPhase::Active);
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
    let mut init = cmd(ToServerCommand::Init);
    init.write_u8(29);
    init.write_u16(0);
    init.write_u16(37);
    init.write_u16(43);
    init.write_utf8("bad name");

    let responses = handler.handle_command(&mut session, &init).unwrap();
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

    let mut init = cmd(ToServerCommand::Init);
    init.write_u8(29);
    init.write_u16(0);
    init.write_u16(1); // min_proto
    init.write_u16(5); // max_proto  -- too old
    init.write_utf8("bob");

    let responses = handler.handle_command(&mut session, &init).unwrap();
    assert_eq!(responses.len(), 1);
    assert_eq!(op_of(&responses[0]), ToClientCommand::AccessDenied);
}

#[test]
fn request_media_accepted_before_init2() {
    // REQUEST_MEDIA is a `Startup`-category opcode in the C++ table
    // (`TOSERVER_STATE_STARTUP`), so `Server::ProcessData` accepts
    // it unconditionally. The Rust port mirrors that: the gate
    // does not reject it, the handler short-circuits with a single
    // empty TOCLIENT_MEDIA bunch (the server has no media
    // registered yet, but it still acknowledges the request).
    let tmp = TempDir::new().unwrap();
    let auth_db = AuthDatabaseSqlite::new(tmp.path()).unwrap();
    let mut handler = CommandHandler::new(37, 43, Box::new(auth_db));

    let peer: SocketAddr = SocketAddrV4::from_str("127.0.0.1:12348").unwrap().into();
    use luanti_network::Session;
    let mut session = Session::new(9, peer);

    let mut init = cmd(ToServerCommand::Init);
    init.write_u8(29);
    init.write_u16(0);
    init.write_u16(37);
    init.write_u16(43);
    init.write_utf8("carol");
    let _ = handler.handle_command(&mut session, &init).unwrap();

    // REQUEST_MEDIA is accepted regardless of phase (Startup
    // category is early-returned in `Server::ProcessData`).
    let mut req = cmd(ToServerCommand::RequestMedia);
    req.write_u16(0);
    let responses = handler.handle_command(&mut session, &req).unwrap();
    assert_eq!(responses.len(), 1);
    assert_eq!(op_of(&responses[0]), ToClientCommand::Media);
    let mut r = WireReader::new(responses[0].as_slice());
    assert_eq!(r.read_u16().unwrap(), 1, "total_bunches");
    assert_eq!(r.read_u16().unwrap(), 0, "bunch_index");
    assert_eq!(r.read_u32().unwrap(), 0, "num_files");
}

#[test]
fn srp_bytes_a_rejects_disallowed_mech() {
    let tmp = TempDir::new().unwrap();
    let auth_db = AuthDatabaseSqlite::new(tmp.path()).unwrap();
    let mut handler = CommandHandler::new(37, 43, Box::new(auth_db));

    let peer: SocketAddr = SocketAddrV4::from_str("127.0.0.1:12349").unwrap().into();
    use luanti_network::Session;
    let mut session = Session::new(10, peer);

    let mut init = cmd(ToServerCommand::Init);
    init.write_u8(29);
    init.write_u16(0);
    init.write_u16(37);
    init.write_u16(43);
    init.write_utf8("dave");
    let _ = handler.handle_command(&mut session, &init).unwrap();

    // After INIT, the server only allows FIRST_SRP (new user).
    // Send SRP_BYTES_A with based_on=0 (legacy) - should be rejected.
    let mut a = cmd(ToServerCommand::SrpBytesA);
    a.write_string(&vec![0u8; 256]);
    a.write_u8(0); // based_on=0 (legacy)
    let responses = handler.handle_command(&mut session, &a).unwrap();
    assert_eq!(responses.len(), 1);
    assert_eq!(op_of(&responses[0]), ToClientCommand::AccessDenied);
}
