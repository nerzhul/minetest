//! End-to-end integration tests for the in-game `ToServerCommand` handlers
//! that don't fit on the auth/handshake critical path.
//!
//! Each test drives a single command through the `CommandHandler` and
//! asserts that the dispatcher-level wire behaviour is strictly
//! equivalent to the C++ server's `Server::handleCommand_*` (same
//! opcode out, same payload, same state transitions).

use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::str::FromStr;

use luanti_auth_db::sqlite::AuthDatabaseSqlite;
use luanti_network::{
    wire::WireReader, InteractAction, ModChannelSignal, NetworkPacket, Session, SessionPhase,
    ToClientCommand, ToServerCommand,
};
use luanti_server::command_handler::CommandHandler;
use tempfile::TempDir;

/// Bring a session up to the `Active` (in-game) phase by replaying the
/// standard INIT → FIRST_SRP → INIT2 → CLIENT_READY sequence. Returns
/// the session in `Active`/`Ingame` state, ready to accept gameplay
/// commands.
fn make_active_session(handler: &mut CommandHandler) -> (Session, SocketAddr) {
    let peer: SocketAddr = SocketAddrV4::from_str("127.0.0.1:30000").unwrap().into();
    let mut session = Session::new(1, peer);

    // 1. INIT
    let mut init = NetworkPacket::new(ToServerCommand::Init as u16, 0);
    init.write_u8(29);
    init.write_u16(0);
    init.write_u16(37);
    init.write_u16(43);
    init.write_utf8("nrz");
    handler
        .handle_command(&mut session, &init)
        .expect("INIT must succeed");

    // 2. FIRST_SRP — use a short test salt/verifier.
    let mut first_srp = NetworkPacket::new(ToServerCommand::FirstSrp as u16, 0);
    first_srp.write_string(b"salt-1234567890ab"); // 16 bytes
    first_srp.write_string(&vec![0xAAu8; 256]); // 256-byte verifier
    first_srp.write_u8(0); // is_empty = false
    handler
        .handle_command(&mut session, &first_srp)
        .expect("FIRST_SRP must succeed");

    // 3. INIT2
    let init2 = NetworkPacket::new(ToServerCommand::Init2 as u16, 0);
    let _ = handler
        .handle_command(&mut session, &init2)
        .expect("INIT2 must succeed");

    // 4. CLIENT_READY
    let mut ready = NetworkPacket::new(ToServerCommand::ClientReady as u16, 0);
    ready.write_u8(5);
    ready.write_u8(9);
    ready.write_u8(0);
    ready.write_u8(0);
    ready.write_utf8("5.9.0");
    handler
        .handle_command(&mut session, &ready)
        .expect("CLIENT_READY must succeed");

    assert_eq!(session.phase, SessionPhase::Active);

    (session, peer)
}

fn make_handler() -> (CommandHandler, TempDir) {
    let tmp = TempDir::new().unwrap();
    let auth_db = AuthDatabaseSqlite::new(tmp.path()).unwrap();
    (CommandHandler::new(37, 43, Box::new(auth_db)), tmp)
}

// ---------------------------------------------------------------------------
// TOSERVER_DELETEDBLOCKS
// ---------------------------------------------------------------------------

#[test]
fn deleted_blocks_acked_without_response() {
    let (mut handler, _tmp) = make_handler();
    let (mut session, _peer) = make_active_session(&mut handler);

    // Wire: u8 count | count * v3s16
    let mut p = NetworkPacket::new(ToServerCommand::DeletedBlocks as u16, 0);
    p.write_u8(2);
    p.write_v3s16(1, 2, 3);
    p.write_v3s16(-4, 5, -6);

    let r = handler.handle_command(&mut session, &p).unwrap();
    assert!(
        r.is_empty(),
        "DELETEDBLOCKS has no response in the C++ server either"
    );
}

// ---------------------------------------------------------------------------
// TOSERVER_DAMAGE
// ---------------------------------------------------------------------------

#[test]
fn damage_parses_u16_payload() {
    let (mut handler, _tmp) = make_handler();
    let (mut session, _peer) = make_active_session(&mut handler);

    let mut p = NetworkPacket::new(ToServerCommand::Damage as u16, 0);
    p.write_u16(7);
    let r = handler.handle_command(&mut session, &p).unwrap();
    assert!(r.is_empty());
}

#[test]
fn damage_truncated_payload_errors() {
    let (mut handler, _tmp) = make_handler();
    let (mut session, _peer) = make_active_session(&mut handler);

    // Empty payload — read_u16 should error.
    let p = NetworkPacket::new(ToServerCommand::Damage as u16, 0);
    assert!(handler.handle_command(&mut session, &p).is_err());
}

// ---------------------------------------------------------------------------
// TOSERVER_PLAYERITEM
// ---------------------------------------------------------------------------

#[test]
fn player_item_parses_u16_payload() {
    let (mut handler, _tmp) = make_handler();
    let (mut session, _peer) = make_active_session(&mut handler);

    let mut p = NetworkPacket::new(ToServerCommand::PlayerItem as u16, 0);
    p.write_u16(3);
    let r = handler.handle_command(&mut session, &p).unwrap();
    assert!(r.is_empty());
}

// ---------------------------------------------------------------------------
// TOSERVER_RESPAWN_LEGACY
// ---------------------------------------------------------------------------

#[test]
fn respawn_legacy_empty_payload() {
    let (mut handler, _tmp) = make_handler();
    let (mut session, _peer) = make_active_session(&mut handler);

    let p = NetworkPacket::new(ToServerCommand::RespawnLegacy as u16, 0);
    let r = handler.handle_command(&mut session, &p).unwrap();
    assert!(r.is_empty());
}

// ---------------------------------------------------------------------------
// TOSERVER_INTERACT
// ---------------------------------------------------------------------------

#[test]
fn interact_digging_completed_at_node_consumes_payload() {
    let (mut handler, _tmp) = make_handler();
    let (mut session, _peer) = make_active_session(&mut handler);

    // Build the wire shape: u8 action | u16 item | u32 plen | PointedThing | writePlayerPos
    let mut p = NetworkPacket::new(ToServerCommand::Interact as u16, 0);
    p.write_u8(InteractAction::DiggingCompleted as u8);
    p.write_u16(0); // wield index

    // PointedThing: u8 version | u8 type (NODE=1) | v3s16 under | v3s16 above
    let mut pt = Vec::new();
    pt.push(0u8); // version
    pt.push(1u8); // POINTEDTHING_NODE
    pt.extend_from_slice(&1i16.to_be_bytes());
    pt.extend_from_slice(&2i16.to_be_bytes());
    pt.extend_from_slice(&3i16.to_be_bytes());
    pt.extend_from_slice(&1i16.to_be_bytes());
    pt.extend_from_slice(&3i16.to_be_bytes());
    pt.extend_from_slice(&3i16.to_be_bytes());

    p.write_u32(pt.len() as u32);
    p.put_raw(&pt);

    // writePlayerPos payload: 12 + 12 + 4 + 4 + 4 + 1 + 1 = 38 bytes
    // (the C++ always emits the always-present block; the 8 optional
    // bytes are version-gated and may be missing).
    p.write_v3s32(100, 200, 300); // position
    p.write_v3s32(0, 0, 0); // speed
    p.write_i32(0); // pitch * 100
    p.write_i32(0); // yaw * 100
    p.write_u32(0); // keyPressed
    p.write_u8(80); // fov * 80
    p.write_u8(5); // wanted_range

    let r = handler.handle_command(&mut session, &p).unwrap();
    assert!(r.is_empty());
}

#[test]
fn interact_unknown_action_is_ignored() {
    let (mut handler, _tmp) = make_handler();
    let (mut session, _peer) = make_active_session(&mut handler);

    let mut p = NetworkPacket::new(ToServerCommand::Interact as u16, 0);
    p.write_u8(0xFE); // unknown
    p.write_u16(0);
    p.write_u32(0); // empty PointedThing (will be skipped)
                    // writePlayerPos (minimal, 38 bytes)
    p.write_v3s32(0, 0, 0);
    p.write_v3s32(0, 0, 0);
    p.write_i32(0);
    p.write_i32(0);
    p.write_u32(0);
    p.write_u8(80);
    p.write_u8(5);

    let r = handler.handle_command(&mut session, &p).unwrap();
    assert!(r.is_empty());
}

#[test]
fn interact_truncated_payload_errors() {
    let (mut handler, _tmp) = make_handler();
    let (mut session, _peer) = make_active_session(&mut handler);

    // No bytes at all — read_u8 should error.
    let p = NetworkPacket::new(ToServerCommand::Interact as u16, 0);
    assert!(handler.handle_command(&mut session, &p).is_err());
}

// ---------------------------------------------------------------------------
// TOSERVER_REMOVED_SOUNDS
// ---------------------------------------------------------------------------

#[test]
fn removed_sounds_parses_count_then_i32s() {
    let (mut handler, _tmp) = make_handler();
    let (mut session, _peer) = make_active_session(&mut handler);

    let mut p = NetworkPacket::new(ToServerCommand::RemovedSounds as u16, 0);
    p.write_u16(2);
    p.write_i32(42);
    p.write_i32(-1);
    let r = handler.handle_command(&mut session, &p).unwrap();
    assert!(r.is_empty());
}

#[test]
fn removed_sounds_empty_count_is_valid() {
    let (mut handler, _tmp) = make_handler();
    let (mut session, _peer) = make_active_session(&mut handler);

    let mut p = NetworkPacket::new(ToServerCommand::RemovedSounds as u16, 0);
    p.write_u16(0);
    let r = handler.handle_command(&mut session, &p).unwrap();
    assert!(r.is_empty());
}

// ---------------------------------------------------------------------------
// TOSERVER_NODEMETA_FIELDS
// ---------------------------------------------------------------------------

#[test]
fn nodemeta_fields_parses_pos_formname_and_field_pairs() {
    let (mut handler, _tmp) = make_handler();
    let (mut session, _peer) = make_active_session(&mut handler);

    let mut p = NetworkPacket::new(ToServerCommand::NodeMetaFields as u16, 0);
    p.write_v3s16(10, 20, 30); // pos
    p.write_utf8("my_form");
    p.write_u16(1); // field_count
    p.write_utf8("key");
    p.write_long_string(b"value");

    let r = handler.handle_command(&mut session, &p).unwrap();
    assert!(r.is_empty());
}

#[test]
fn nodemeta_fields_oversized_payload_is_rejected() {
    let (mut handler, _tmp) = make_handler();
    let (mut session, _peer) = make_active_session(&mut handler);

    let mut p = NetworkPacket::new(ToServerCommand::NodeMetaFields as u16, 0);
    p.write_v3s16(0, 0, 0);
    p.write_utf8("big");
    p.write_u16(1);
    p.write_utf8("k");
    // Force the size check to trip: C++ uses a 640 KiB limit.
    p.write_long_string(&vec![0u8; 700 * 1024]);

    let r = handler.handle_command(&mut session, &p).unwrap();
    assert!(r.is_empty());
}

// ---------------------------------------------------------------------------
// TOSERVER_INVENTORY_FIELDS
// ---------------------------------------------------------------------------

#[test]
fn inventory_fields_parses_formname_and_field_pairs() {
    let (mut handler, _tmp) = make_handler();
    let (mut session, _peer) = make_active_session(&mut handler);

    let mut p = NetworkPacket::new(ToServerCommand::InventoryFields as u16, 0);
    p.write_utf8(""); // empty formname = pass-through to on_playerReceiveFields
    p.write_u16(2);
    p.write_utf8("quit");
    p.write_long_string(b"true");
    p.write_utf8("x");
    p.write_long_string(b"1");

    let r = handler.handle_command(&mut session, &p).unwrap();
    assert!(r.is_empty());
}

// ---------------------------------------------------------------------------
// TOSERVER_INVENTORY_ACTION
// ---------------------------------------------------------------------------

#[test]
fn inventory_action_consumes_raw_blob() {
    let (mut handler, _tmp) = make_handler();
    let (mut session, _peer) = make_active_session(&mut handler);

    // The C++ client writes the action's text serialization WITHOUT a
    // length prefix (raw bytes, see `Client::sendInventoryAction`). We
    // emit a plausible "Move 1 player:nrz\n main 0 player:nrz\n craftresult 1\n"
    // action just like the C++ istringstream parser expects.
    let mut p = NetworkPacket::new(ToServerCommand::InventoryAction as u16, 0);
    p.put_raw(b"Move 1 player:nrz\n main 0 player:nrz\n craftresult 1\n");

    let r = handler.handle_command(&mut session, &p).unwrap();
    assert!(r.is_empty());
}

// ---------------------------------------------------------------------------
// TOSERVER_MODCHANNEL_*
// ---------------------------------------------------------------------------

#[test]
fn modchannel_join_returns_join_failure_signal() {
    let (mut handler, _tmp) = make_handler();
    let (mut session, _peer) = make_active_session(&mut handler);

    let mut p = NetworkPacket::new(ToServerCommand::ModChannelJoin as u16, 0);
    p.write_utf8("mychan");

    let r = handler.handle_command(&mut session, &p).unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].command(), ToClientCommand::ModChannelSignal as u16);
    // u8 signal byte
    assert_eq!(r[0].as_slice()[0], ModChannelSignal::JoinFailure as u8);
    // The channel name follows (u16 length + bytes).
    let mut rd = WireReader::new(r[0].as_slice());
    rd.read_u8().unwrap();
    assert_eq!(rd.read_utf8().unwrap(), "mychan");
}

#[test]
fn modchannel_leave_returns_leave_ok_signal() {
    let (mut handler, _tmp) = make_handler();
    let (mut session, _peer) = make_active_session(&mut handler);

    let mut p = NetworkPacket::new(ToServerCommand::ModChannelLeave as u16, 0);
    p.write_utf8("mychan");

    let r = handler.handle_command(&mut session, &p).unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].command(), ToClientCommand::ModChannelSignal as u16);
    assert_eq!(r[0].as_slice()[0], ModChannelSignal::LeaveOk as u8);
}

#[test]
fn modchannel_msg_silently_dropped() {
    let (mut handler, _tmp) = make_handler();
    let (mut session, _peer) = make_active_session(&mut handler);

    let mut p = NetworkPacket::new(ToServerCommand::ModChannelMsg as u16, 0);
    p.write_utf8("mychan");
    p.write_utf8("hello world");

    let r = handler.handle_command(&mut session, &p).unwrap();
    assert!(r.is_empty());
}

// ---------------------------------------------------------------------------
// TOSERVER_UPDATE_CLIENT_INFO
// ---------------------------------------------------------------------------

#[test]
fn update_client_info_parses_full_payload() {
    let (mut handler, _tmp) = make_handler();
    let (mut session, _peer) = make_active_session(&mut handler);

    let mut p = NetworkPacket::new(ToServerCommand::UpdateClientInfo as u16, 0);
    p.write_i32(1920); // render_target_size.X
    p.write_i32(1080); // render_target_size.Y
    p.write_f32(1.5); // real_gui_scaling
    p.write_f32(2.0); // real_hud_scaling
    p.write_i32(1920); // max_fs_size.X
    p.write_i32(1080); // max_fs_size.Y
    p.write_u8(1); // touch_controls (added 5.9.0)

    let r = handler.handle_command(&mut session, &p).unwrap();
    assert!(r.is_empty());
}

#[test]
fn update_client_info_truncated_payload_is_silently_ignored() {
    let (mut handler, _tmp) = make_handler();
    let (mut session, _peer) = make_active_session(&mut handler);

    // 10 bytes < 24 required → ignored (matches the C++ try/catch
    // around the read).
    let mut p = NetworkPacket::new(ToServerCommand::UpdateClientInfo as u16, 0);
    p.write_i32(0);
    p.write_i32(0);
    p.write_f32(1.0);
    p.write_f32(1.0);

    let r = handler.handle_command(&mut session, &p).unwrap();
    assert!(r.is_empty());
}
