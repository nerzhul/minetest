// Opcodes and command definitions for the Luanti protocol
// Based on ToServerCommand and ToClientCommand enums.
//
// The opcode metadata (name, required connection-state, send
// channel, reliability) is stored in two static lookup tables
// indexed by the wire value, mirroring the C++ `toServerCommandTable`
// and `clientCommandFactoryTable` arrays in
// `src/network/serveropcodes.cpp` and `clientopcodes.cpp`. The
// `ToServerCommand` / `ToClientCommand` enums stay as type-safe
// handles (so call-sites get exhaustiveness checking) and their
// `name()` / `required_state()` / `channel()` / `is_reliable()`
// accessors are thin lookups into the table — there is no parallel
// `match` to keep in sync with the data.

use std::fmt;

/// Size of the server-side opcode table. Must match
/// `TOSERVER_NUM_MSG_TYPES` in
/// `src/network/networkprotocol.h`.
pub const TOSERVER_NUM_MSG_TYPES: usize = 0x54;

/// Size of the client-side opcode table. Must match
/// `TOCLIENT_NUM_MSG_TYPES` in
/// `src/network/networkprotocol.h`.
pub const TOCLIENT_NUM_MSG_TYPES: usize = 0x65;

/// Metadata for a single `TOSERVER_*` opcode. Mirrors the
/// `ToServerCommandHandler` struct in `src/network/serveropcodes.h`
/// minus the function pointer (the Rust port dispatches via a
/// `match` on the `ToServerCommand` enum in `command_handler.rs`
/// — see the "Command dispatch" section in
/// `rust/luanti-server/src/command_handler.rs`).
#[derive(Debug, Clone, Copy)]
pub struct ToServerCommandSpec {
    /// Human-readable name (e.g. `"TOSERVER_INIT"`), used in logs
    /// and wire-level error messages.
    pub name: &'static str,
    /// Connection-state category that gates this opcode in
    /// `Server::ProcessData` (and the Rust port's
    /// `CommandHandler::check_command_state`).
    pub required_state: ToServerConnectionState,
}

/// Server-side opcode table, indexed by the on-the-wire `u16`
/// opcode. Each non-null slot is a `ToServerCommandSpec`; null
/// slots correspond to unassigned opcodes (the C++ source fills
/// those with a `null_command_handler` of category `ALL`).
///
/// **Source of truth**: this table mirrors the
/// `toServerCommandTable[TOSERVER_NUM_MSG_TYPES]` array literal in
/// `src/network/serveropcodes.cpp` line-for-line. Any change to
/// the C++ table must be reflected here.
static TO_SERVER_COMMAND_TABLE: [Option<ToServerCommandSpec>; TOSERVER_NUM_MSG_TYPES] = [
    None, // 0x00 (never used)
    None, // 0x01
    Some(ToServerCommandSpec {
        name: "TOSERVER_INIT",
        required_state: ToServerConnectionState::NotConnected,
    }), // 0x02
    None, // 0x03
    None, // 0x04
    None, // 0x05
    None, // 0x06
    None, // 0x07
    None, // 0x08
    None, // 0x09
    None, // 0x0a
    None, // 0x0b
    None, // 0x0c
    None, // 0x0d
    None, // 0x0e
    None, // 0x0f
    None, // 0x10
    Some(ToServerCommandSpec {
        name: "TOSERVER_INIT2",
        required_state: ToServerConnectionState::NotConnected,
    }), // 0x11
    None, // 0x12
    None, // 0x13
    None, // 0x14
    None, // 0x15
    None, // 0x16
    Some(ToServerCommandSpec {
        name: "TOSERVER_MODCHANNEL_JOIN",
        required_state: ToServerConnectionState::Ingame,
    }), // 0x17
    Some(ToServerCommandSpec {
        name: "TOSERVER_MODCHANNEL_LEAVE",
        required_state: ToServerConnectionState::Ingame,
    }), // 0x18
    Some(ToServerCommandSpec {
        name: "TOSERVER_MODCHANNEL_MSG",
        required_state: ToServerConnectionState::Ingame,
    }), // 0x19
    None, // 0x1a
    None, // 0x1b
    None, // 0x1c
    None, // 0x1d
    None, // 0x1e
    None, // 0x1f
    None, // 0x20
    None, // 0x21
    None, // 0x22
    Some(ToServerCommandSpec {
        name: "TOSERVER_PLAYERPOS",
        required_state: ToServerConnectionState::Ingame,
    }), // 0x23
    Some(ToServerCommandSpec {
        name: "TOSERVER_GOTBLOCKS",
        required_state: ToServerConnectionState::Startup,
    }), // 0x24
    Some(ToServerCommandSpec {
        name: "TOSERVER_DELETEDBLOCKS",
        required_state: ToServerConnectionState::Ingame,
    }), // 0x25
    None, // 0x26
    None, // 0x27
    None, // 0x28
    None, // 0x29
    None, // 0x2a
    None, // 0x2b
    None, // 0x2c
    None, // 0x2d
    None, // 0x2e
    None, // 0x2f
    None, // 0x30
    Some(ToServerCommandSpec {
        name: "TOSERVER_INVENTORY_ACTION",
        required_state: ToServerConnectionState::Ingame,
    }), // 0x31
    Some(ToServerCommandSpec {
        name: "TOSERVER_CHAT_MESSAGE",
        required_state: ToServerConnectionState::Ingame,
    }), // 0x32
    None, // 0x33
    None, // 0x34
    Some(ToServerCommandSpec {
        name: "TOSERVER_DAMAGE",
        required_state: ToServerConnectionState::Ingame,
    }), // 0x35
    None, // 0x36
    Some(ToServerCommandSpec {
        name: "TOSERVER_PLAYERITEM",
        required_state: ToServerConnectionState::Ingame,
    }), // 0x37
    // 0x38: TOSERVER_RESPAWN_LEGACY. The C++ server defines this in
    // its `ToServerCommand` enum but leaves the dispatch table slot
    // empty (a `null_command_handler` of category `TOSERVER_STATE_ALL`).
    // The Rust port implements a real handler (legacy respawn for
    // clients < 5.0.0 that predate the modern death-screen
    // formspec), so we give it a concrete entry. The state is
    // `Ingame` because respawning is only meaningful in-game; the
    // C++ effectively accepts it at any state because its null
    // handler is a no-op.
    Some(ToServerCommandSpec {
        name: "TOSERVER_RESPAWN_LEGACY",
        required_state: ToServerConnectionState::Ingame,
    }), // 0x38
    Some(ToServerCommandSpec {
        name: "TOSERVER_INTERACT",
        required_state: ToServerConnectionState::Ingame,
    }), // 0x39
    Some(ToServerCommandSpec {
        name: "TOSERVER_REMOVED_SOUNDS",
        required_state: ToServerConnectionState::Ingame,
    }), // 0x3a
    Some(ToServerCommandSpec {
        name: "TOSERVER_NODEMETA_FIELDS",
        required_state: ToServerConnectionState::Ingame,
    }), // 0x3b
    Some(ToServerCommandSpec {
        name: "TOSERVER_INVENTORY_FIELDS",
        required_state: ToServerConnectionState::Ingame,
    }), // 0x3c
    None, // 0x3d
    None, // 0x3e
    None, // 0x3f
    Some(ToServerCommandSpec {
        name: "TOSERVER_REQUEST_MEDIA",
        required_state: ToServerConnectionState::Startup,
    }), // 0x40
    Some(ToServerCommandSpec {
        name: "TOSERVER_HAVE_MEDIA",
        required_state: ToServerConnectionState::Ingame,
    }), // 0x41
    None, // 0x42
    Some(ToServerCommandSpec {
        name: "TOSERVER_CLIENT_READY",
        required_state: ToServerConnectionState::Startup,
    }), // 0x43
    None, // 0x44
    None, // 0x45
    None, // 0x46
    None, // 0x47
    None, // 0x48
    None, // 0x49
    None, // 0x4a
    None, // 0x4b
    None, // 0x4c
    None, // 0x4d
    None, // 0x4e
    None, // 0x4f
    Some(ToServerCommandSpec {
        name: "TOSERVER_FIRST_SRP",
        required_state: ToServerConnectionState::NotConnected,
    }), // 0x50
    Some(ToServerCommandSpec {
        name: "TOSERVER_SRP_BYTES_A",
        required_state: ToServerConnectionState::NotConnected,
    }), // 0x51
    Some(ToServerCommandSpec {
        name: "TOSERVER_SRP_BYTES_M",
        required_state: ToServerConnectionState::NotConnected,
    }), // 0x52
    Some(ToServerCommandSpec {
        name: "TOSERVER_UPDATE_CLIENT_INFO",
        required_state: ToServerConnectionState::Ingame,
    }), // 0x53
];

/// Look up a `ToServerCommandSpec` by raw wire opcode.
///
/// This is the table-driven equivalent of the C++
///
/// ```cpp
/// if (command < TOSERVER_NUM_MSG_TYPES
///         && toServerCommandTable[command].state != TOSERVER_STATE_ALL)
///     handle();
/// ```
///
/// pattern. Returns `None` for unassigned opcodes (so the caller
/// can log "Unknown command" and drop the packet, exactly like the
/// C++ `handleCommand_Deprecated` path).
pub fn lookup_to_server_command(value: u16) -> Option<ToServerCommandSpec> {
    TO_SERVER_COMMAND_TABLE
        .get(value as usize)
        .and_then(|slot| *slot)
}

/// Commands that can be sent from client to server.
///
/// The discriminants must match the on-the-wire opcode values; the
/// enum is the type-safe view of `TO_SERVER_COMMAND_TABLE` and the
/// two stay in lock-step.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ToServerCommand {
    Init = 0x02,
    Init2 = 0x11,
    ModChannelJoin = 0x17,
    ModChannelLeave = 0x18,
    ModChannelMsg = 0x19,
    PlayerPos = 0x23,
    GotBlocks = 0x24,
    DeletedBlocks = 0x25,
    InventoryAction = 0x31,
    ChatMessage = 0x32,
    Damage = 0x35,
    PlayerItem = 0x37,
    RespawnLegacy = 0x38,
    Interact = 0x39,
    RemovedSounds = 0x3a,
    NodeMetaFields = 0x3b,
    InventoryFields = 0x3c,
    RequestMedia = 0x40,
    HaveMedia = 0x41,
    ClientReady = 0x43,
    FirstSrp = 0x50,
    SrpBytesA = 0x51,
    SrpBytesM = 0x52,
    UpdateClientInfo = 0x53,
}

impl ToServerCommand {
    /// Decode a wire opcode to its enum variant. Inverse of the
    /// `#[repr(u16)]` discriminant.
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x02 => Some(Self::Init),
            0x11 => Some(Self::Init2),
            0x17 => Some(Self::ModChannelJoin),
            0x18 => Some(Self::ModChannelLeave),
            0x19 => Some(Self::ModChannelMsg),
            0x23 => Some(Self::PlayerPos),
            0x24 => Some(Self::GotBlocks),
            0x25 => Some(Self::DeletedBlocks),
            0x31 => Some(Self::InventoryAction),
            0x32 => Some(Self::ChatMessage),
            0x35 => Some(Self::Damage),
            0x37 => Some(Self::PlayerItem),
            0x38 => Some(Self::RespawnLegacy),
            0x39 => Some(Self::Interact),
            0x3a => Some(Self::RemovedSounds),
            0x3b => Some(Self::NodeMetaFields),
            0x3c => Some(Self::InventoryFields),
            0x40 => Some(Self::RequestMedia),
            0x41 => Some(Self::HaveMedia),
            0x43 => Some(Self::ClientReady),
            0x50 => Some(Self::FirstSrp),
            0x51 => Some(Self::SrpBytesA),
            0x52 => Some(Self::SrpBytesM),
            0x53 => Some(Self::UpdateClientInfo),
            _ => None,
        }
    }

    /// Human-readable name. Backed by `TO_SERVER_COMMAND_TABLE` —
    /// the table is the single source of truth, this method is a
    /// typed wrapper around it.
    pub fn name(&self) -> &'static str {
        self.spec().name
    }

    /// Connection-state category the server expects the peer to be
    /// in. Mirrors `toServerCommandTable[command].state` in
    /// [`src/network/serveropcodes.cpp`](../../../../src/network/serveropcodes.cpp).
    ///
    /// The C++ `Server::ProcessData` early-returns on
    /// `NotConnected` and `Startup` (no `ClientState` check) and
    /// only consults state for `Ingame`. The Rust
    /// `CommandHandler::check_command_state` mirrors that dispatch.
    pub fn required_state(&self) -> ToServerConnectionState {
        self.spec().required_state
    }

    /// Direct access to the table entry for this opcode.
    fn spec(&self) -> ToServerCommandSpec {
        lookup_to_server_command(*self as u16).expect("ToServerCommand variant has no table entry")
    }
}

impl fmt::Display for ToServerCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Metadata for a single `TOCLIENT_*` opcode. Mirrors the
/// `ClientCommandFactory` struct in `src/network/serveropcodes.h`.
#[derive(Debug, Clone, Copy)]
pub struct ToClientCommandSpec {
    /// Human-readable name (e.g. `"TOCLIENT_HELLO"`).
    pub name: &'static str,
    /// MTP channel the command is sent on. Most commands use
    /// channel 0; block data uses channel 2 (bulk); HUD commands
    /// use channel 1.
    pub channel: u8,
    /// Whether the command is sent reliably. Block data is the
    /// one exception because it can simply be re-requested by the
    /// client on loss.
    pub reliable: bool,
}

/// Client-side opcode table, indexed by the on-the-wire `u16`
/// opcode. Mirrors the `clientCommandFactoryTable[TOCLIENT_NUM_MSG_TYPES]`
/// array in `src/network/serveropcodes.cpp` line-for-line.
static TO_CLIENT_COMMAND_TABLE: [Option<ToClientCommandSpec>; TOCLIENT_NUM_MSG_TYPES] = [
    None, // 0x00
    None, // 0x01
    Some(ToClientCommandSpec {
        name: "TOCLIENT_HELLO",
        channel: 0,
        reliable: true,
    }), // 0x02
    Some(ToClientCommandSpec {
        name: "TOCLIENT_AUTH_ACCEPT",
        channel: 0,
        reliable: true,
    }), // 0x03
    Some(ToClientCommandSpec {
        name: "TOCLIENT_ACCEPT_SUDO_MODE",
        channel: 0,
        reliable: true,
    }), // 0x04
    Some(ToClientCommandSpec {
        name: "TOCLIENT_DENY_SUDO_MODE",
        channel: 0,
        reliable: true,
    }), // 0x05
    None, // 0x06
    None, // 0x07
    None, // 0x08
    None, // 0x09
    Some(ToClientCommandSpec {
        name: "TOCLIENT_ACCESS_DENIED",
        channel: 0,
        reliable: true,
    }), // 0x0A
    None, // 0x0B
    None, // 0x0C
    None, // 0x0D
    None, // 0x0E
    None, // 0x0F
    None, // 0x10
    None, // 0x11
    None, // 0x12
    None, // 0x13
    None, // 0x14
    None, // 0x15
    None, // 0x16
    None, // 0x17
    None, // 0x18
    None, // 0x19
    None, // 0x1A
    None, // 0x1B
    None, // 0x1C
    None, // 0x1D
    None, // 0x1E
    None, // 0x1F
    Some(ToClientCommandSpec {
        name: "TOCLIENT_BLOCKDATA",
        channel: 2,
        reliable: false,
    }), // 0x20
    Some(ToClientCommandSpec {
        name: "TOCLIENT_ADDNODE",
        channel: 0,
        reliable: true,
    }), // 0x21
    Some(ToClientCommandSpec {
        name: "TOCLIENT_REMOVENODE",
        channel: 0,
        reliable: true,
    }), // 0x22
    None, // 0x23
    None, // 0x24
    None, // 0x25
    None, // 0x26
    Some(ToClientCommandSpec {
        name: "TOCLIENT_INVENTORY",
        channel: 0,
        reliable: true,
    }), // 0x27
    None, // 0x28
    Some(ToClientCommandSpec {
        name: "TOCLIENT_TIME_OF_DAY",
        channel: 0,
        reliable: true,
    }), // 0x29
    Some(ToClientCommandSpec {
        name: "TOCLIENT_CSM_RESTRICTION_FLAGS",
        channel: 0,
        reliable: true,
    }), // 0x2A
    Some(ToClientCommandSpec {
        name: "TOCLIENT_PLAYER_SPEED",
        channel: 0,
        reliable: true,
    }), // 0x2B
    Some(ToClientCommandSpec {
        name: "TOCLIENT_MEDIA_PUSH",
        channel: 0,
        reliable: true,
    }), // 0x2C (sent on channel 1 too if legacy)
    None, // 0x2D
    None, // 0x2E
    Some(ToClientCommandSpec {
        name: "TOCLIENT_CHAT_MESSAGE",
        channel: 0,
        reliable: true,
    }), // 0x2F
    None, // 0x30
    Some(ToClientCommandSpec {
        name: "TOCLIENT_ACTIVE_OBJECT_REMOVE_ADD",
        channel: 0,
        reliable: true,
    }), // 0x31
    Some(ToClientCommandSpec {
        name: "TOCLIENT_ACTIVE_OBJECT_MESSAGES",
        channel: 0,
        reliable: true,
    }), // 0x32 (may also be sent unrel on channel 1)
    Some(ToClientCommandSpec {
        name: "TOCLIENT_HP",
        channel: 0,
        reliable: true,
    }), // 0x33
    Some(ToClientCommandSpec {
        name: "TOCLIENT_MOVE_PLAYER",
        channel: 0,
        reliable: true,
    }), // 0x34
    Some(ToClientCommandSpec {
        name: "TOCLIENT_ACCESS_DENIED_LEGACY",
        channel: 0,
        reliable: true,
    }), // 0x35
    Some(ToClientCommandSpec {
        name: "TOCLIENT_FOV",
        channel: 0,
        reliable: true,
    }), // 0x36
    Some(ToClientCommandSpec {
        name: "TOCLIENT_DEATHSCREEN_LEGACY",
        channel: 0,
        reliable: true,
    }), // 0x37
    Some(ToClientCommandSpec {
        name: "TOCLIENT_MEDIA",
        channel: 2,
        reliable: true,
    }), // 0x38
    None, // 0x39
    Some(ToClientCommandSpec {
        name: "TOCLIENT_NODEDEF",
        channel: 0,
        reliable: true,
    }), // 0x3A
    None, // 0x3B
    Some(ToClientCommandSpec {
        name: "TOCLIENT_ANNOUNCE_MEDIA",
        channel: 0,
        reliable: true,
    }), // 0x3C
    Some(ToClientCommandSpec {
        name: "TOCLIENT_ITEMDEF",
        channel: 0,
        reliable: true,
    }), // 0x3D
    None, // 0x3E
    Some(ToClientCommandSpec {
        name: "TOCLIENT_PLAY_SOUND",
        channel: 0,
        reliable: true,
    }), // 0x3F (may also be sent unrel)
    Some(ToClientCommandSpec {
        name: "TOCLIENT_STOP_SOUND",
        channel: 0,
        reliable: true,
    }), // 0x40
    Some(ToClientCommandSpec {
        name: "TOCLIENT_PRIVILEGES",
        channel: 0,
        reliable: true,
    }), // 0x41
    Some(ToClientCommandSpec {
        name: "TOCLIENT_INVENTORY_FORMSPEC",
        channel: 0,
        reliable: true,
    }), // 0x42
    Some(ToClientCommandSpec {
        name: "TOCLIENT_DETACHED_INVENTORY",
        channel: 0,
        reliable: true,
    }), // 0x43
    Some(ToClientCommandSpec {
        name: "TOCLIENT_SHOW_FORMSPEC",
        channel: 0,
        reliable: true,
    }), // 0x44
    Some(ToClientCommandSpec {
        name: "TOCLIENT_MOVEMENT",
        channel: 0,
        reliable: true,
    }), // 0x45
    Some(ToClientCommandSpec {
        name: "TOCLIENT_SPAWN_PARTICLE",
        channel: 0,
        reliable: true,
    }), // 0x46
    Some(ToClientCommandSpec {
        name: "TOCLIENT_ADD_PARTICLESPAWNER",
        channel: 0,
        reliable: true,
    }), // 0x47
    Some(ToClientCommandSpec {
        name: "TOCLIENT_CAMERA",
        channel: 0,
        reliable: true,
    }), // 0x48
    Some(ToClientCommandSpec {
        name: "TOCLIENT_HUDADD",
        channel: 1,
        reliable: true,
    }), // 0x49
    Some(ToClientCommandSpec {
        name: "TOCLIENT_HUDRM",
        channel: 1,
        reliable: true,
    }), // 0x4A
    Some(ToClientCommandSpec {
        name: "TOCLIENT_HUDCHANGE",
        channel: 1,
        reliable: true,
    }), // 0x4B
    Some(ToClientCommandSpec {
        name: "TOCLIENT_HUD_SET_FLAGS",
        channel: 1,
        reliable: true,
    }), // 0x4C
    Some(ToClientCommandSpec {
        name: "TOCLIENT_HUD_SET_PARAM",
        channel: 1,
        reliable: true,
    }), // 0x4D
    Some(ToClientCommandSpec {
        name: "TOCLIENT_BREATH",
        channel: 0,
        reliable: true,
    }), // 0x4E
    Some(ToClientCommandSpec {
        name: "TOCLIENT_SET_SKY",
        channel: 0,
        reliable: true,
    }), // 0x4F
    Some(ToClientCommandSpec {
        name: "TOCLIENT_OVERRIDE_DAY_NIGHT_RATIO",
        channel: 0,
        reliable: true,
    }), // 0x50
    Some(ToClientCommandSpec {
        name: "TOCLIENT_LOCAL_PLAYER_ANIMATIONS",
        channel: 0,
        reliable: true,
    }), // 0x51
    Some(ToClientCommandSpec {
        name: "TOCLIENT_EYE_OFFSET",
        channel: 0,
        reliable: true,
    }), // 0x52
    Some(ToClientCommandSpec {
        name: "TOCLIENT_DELETE_PARTICLESPAWNER",
        channel: 0,
        reliable: true,
    }), // 0x53
    Some(ToClientCommandSpec {
        name: "TOCLIENT_CLOUD_PARAMS",
        channel: 0,
        reliable: true,
    }), // 0x54
    Some(ToClientCommandSpec {
        name: "TOCLIENT_FADE_SOUND",
        channel: 0,
        reliable: true,
    }), // 0x55
    Some(ToClientCommandSpec {
        name: "TOCLIENT_UPDATE_PLAYER_LIST",
        channel: 0,
        reliable: true,
    }), // 0x56
    Some(ToClientCommandSpec {
        name: "TOCLIENT_MODCHANNEL_MSG",
        channel: 0,
        reliable: true,
    }), // 0x57
    Some(ToClientCommandSpec {
        name: "TOCLIENT_MODCHANNEL_SIGNAL",
        channel: 0,
        reliable: true,
    }), // 0x58
    Some(ToClientCommandSpec {
        name: "TOCLIENT_NODEMETA_CHANGED",
        channel: 0,
        reliable: true,
    }), // 0x59
    Some(ToClientCommandSpec {
        name: "TOCLIENT_SET_SUN",
        channel: 0,
        reliable: true,
    }), // 0x5A
    Some(ToClientCommandSpec {
        name: "TOCLIENT_SET_MOON",
        channel: 0,
        reliable: true,
    }), // 0x5B
    Some(ToClientCommandSpec {
        name: "TOCLIENT_SET_STARS",
        channel: 0,
        reliable: true,
    }), // 0x5C
    Some(ToClientCommandSpec {
        name: "TOCLIENT_MOVE_PLAYER_REL",
        channel: 0,
        reliable: true,
    }), // 0x5D
    None, // 0x5E
    None, // 0x5F
    Some(ToClientCommandSpec {
        name: "TOCLIENT_SRP_BYTES_S_B",
        channel: 0,
        reliable: true,
    }), // 0x60
    Some(ToClientCommandSpec {
        name: "TOCLIENT_FORMSPEC_PREPEND",
        channel: 0,
        reliable: true,
    }), // 0x61
    Some(ToClientCommandSpec {
        name: "TOCLIENT_MINIMAP_MODES",
        channel: 0,
        reliable: true,
    }), // 0x62
    Some(ToClientCommandSpec {
        name: "TOCLIENT_SET_LIGHTING",
        channel: 0,
        reliable: true,
    }), // 0x63
    Some(ToClientCommandSpec {
        name: "TOCLIENT_SPAWN_PARTICLE_BATCH",
        channel: 0,
        reliable: true,
    }), // 0x64
];

/// Look up a `ToClientCommandSpec` by raw wire opcode.
pub fn lookup_to_client_command(value: u16) -> Option<ToClientCommandSpec> {
    TO_CLIENT_COMMAND_TABLE
        .get(value as usize)
        .and_then(|slot| *slot)
}

/// Commands that can be sent from server to client.
///
/// Discriminants match the on-the-wire opcode values; the enum is
/// the type-safe view of `TO_CLIENT_COMMAND_TABLE`.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ToClientCommand {
    Hello = 0x02,
    AuthAccept = 0x03,
    AcceptSudoMode = 0x04,
    DenySudoMode = 0x05,
    AccessDenied = 0x0A,
    BlockData = 0x20,
    AddNode = 0x21,
    RemoveNode = 0x22,
    Inventory = 0x27,
    TimeOfDay = 0x29,
    CsmRestrictionFlags = 0x2A,
    PlayerSpeed = 0x2B,
    MediaPush = 0x2C,
    ChatMessage = 0x2F,
    ActiveObjectRemoveAdd = 0x31,
    ActiveObjectMessages = 0x32,
    Hp = 0x33,
    MovePlayer = 0x34,
    AccessDeniedLegacy = 0x35,
    Fov = 0x36,
    DeathScreenLegacy = 0x37,
    Media = 0x38,
    NodeDef = 0x3a,
    AnnounceMedia = 0x3c,
    ItemDef = 0x3d,
    PlaySound = 0x3f,
    StopSound = 0x40,
    Privileges = 0x41,
    InventoryFormspec = 0x42,
    DetachedInventory = 0x43,
    ShowFormspec = 0x44,
    Movement = 0x45,
    SpawnParticle = 0x46,
    AddParticleSpawner = 0x47,
    Camera = 0x48,
    HudAdd = 0x49,
    HudRm = 0x4a,
    HudChange = 0x4b,
    HudSetFlags = 0x4c,
    HudSetParam = 0x4d,
    Breath = 0x4e,
    SetSky = 0x4f,
    SrpBytesSB = 0x60,
    ModChannelMsg = 0x57,
    ModChannelSignal = 0x58,
}

impl ToClientCommand {
    /// Decode a wire opcode to its enum variant. Inverse of the
    /// `#[repr(u16)]` discriminant.
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x02 => Some(Self::Hello),
            0x03 => Some(Self::AuthAccept),
            0x04 => Some(Self::AcceptSudoMode),
            0x05 => Some(Self::DenySudoMode),
            0x0A => Some(Self::AccessDenied),
            0x20 => Some(Self::BlockData),
            0x21 => Some(Self::AddNode),
            0x22 => Some(Self::RemoveNode),
            0x27 => Some(Self::Inventory),
            0x29 => Some(Self::TimeOfDay),
            0x2A => Some(Self::CsmRestrictionFlags),
            0x2B => Some(Self::PlayerSpeed),
            0x2C => Some(Self::MediaPush),
            0x2F => Some(Self::ChatMessage),
            0x31 => Some(Self::ActiveObjectRemoveAdd),
            0x32 => Some(Self::ActiveObjectMessages),
            0x33 => Some(Self::Hp),
            0x34 => Some(Self::MovePlayer),
            0x35 => Some(Self::AccessDeniedLegacy),
            0x36 => Some(Self::Fov),
            0x37 => Some(Self::DeathScreenLegacy),
            0x38 => Some(Self::Media),
            0x3a => Some(Self::NodeDef),
            0x3c => Some(Self::AnnounceMedia),
            0x3d => Some(Self::ItemDef),
            0x3f => Some(Self::PlaySound),
            0x40 => Some(Self::StopSound),
            0x41 => Some(Self::Privileges),
            0x42 => Some(Self::InventoryFormspec),
            0x43 => Some(Self::DetachedInventory),
            0x44 => Some(Self::ShowFormspec),
            0x45 => Some(Self::Movement),
            0x46 => Some(Self::SpawnParticle),
            0x47 => Some(Self::AddParticleSpawner),
            0x48 => Some(Self::Camera),
            0x49 => Some(Self::HudAdd),
            0x4a => Some(Self::HudRm),
            0x4b => Some(Self::HudChange),
            0x4c => Some(Self::HudSetFlags),
            0x4d => Some(Self::HudSetParam),
            0x4e => Some(Self::Breath),
            0x4f => Some(Self::SetSky),
            0x60 => Some(Self::SrpBytesSB),
            0x57 => Some(Self::ModChannelMsg),
            0x58 => Some(Self::ModChannelSignal),
            _ => None,
        }
    }

    /// Human-readable name. Backed by `TO_CLIENT_COMMAND_TABLE`.
    pub fn name(&self) -> &'static str {
        self.spec().name
    }

    /// MTP channel the command is sent on. Backed by
    /// `TO_CLIENT_COMMAND_TABLE`; mirrors
    /// `clientCommandFactoryTable[i].channel` in the C++ source.
    pub fn channel(&self) -> u8 {
        self.spec().channel
    }

    /// Whether the command is sent reliably. Backed by
    /// `TO_CLIENT_COMMAND_TABLE`; mirrors
    /// `clientCommandFactoryTable[i].reliable` in the C++ source.
    pub fn is_reliable(&self) -> bool {
        self.spec().reliable
    }

    /// Direct access to the table entry for this opcode.
    fn spec(&self) -> ToClientCommandSpec {
        lookup_to_client_command(*self as u16).expect("ToClientCommand variant has no table entry")
    }
}

impl fmt::Display for ToClientCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Coarse three-way connection-state category for server-side
/// command gating. Mirrors `enum ToServerConnectionState` in
/// [`src/network/serveropcodes.h`](../../../../src/network/serveropcodes.h).
///
/// In the C++ server this is *not* a per-session state — it is a
/// property of the opcode (see `toServerCommandTable[i].state`).
/// `Server::ProcessData` reads the opcode's category and dispatches:
///
/// * `NotConnected` (`TOSERVER_STATE_NOT_CONNECTED = 0`) and
///   `Startup` (`TOSERVER_STATE_STARTUP = 1`) are early-returned
///   with no `ClientState` check.
/// * `Ingame` (`TOSERVER_STATE_INGAME = 2`) requires
///   `m_clients.getClientState(peer_id) >= CS_Active`.
/// * `All` (`TOSERVER_STATE_ALL = 3`) is a sentinel used in the
///   null-command handler table; no real opcode is in this category
///   but it is kept for completeness.
///
/// The Rust port uses the same discriminants so a `#[repr(u8)]`
/// representation matches the C++ `u8` enum byte-for-byte.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToServerConnectionState {
    NotConnected = 0,
    Startup = 1,
    Ingame = 2,
    All = 3,
}

/// Connection state for client processing server commands
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToClientConnectionState {
    NotConnected,
    Connected,
}

/// Auth mechanisms supported by the protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMechanism {
    None = 0,
    LegacyPassword = 1 << 0,
    Srp = 1 << 1,
    FirstSrp = 1 << 2,
}

/// Access denied error codes
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessDeniedCode {
    WrongPassword = 0,
    UnexpectedData = 1,
    Singleplayer = 2,
    WrongVersion = 3,
    WrongCharsInName = 4,
    WrongName = 5,
    TooManyUsers = 6,
    EmptyPassword = 7,
    AlreadyConnected = 8,
    ServerFail = 9,
    CustomString = 10,
    Shutdown = 11,
    Crash = 12,
}

/// Interact action types
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InteractAction {
    StartDigging = 0,
    StopDigging = 1,
    DiggingCompleted = 2,
    Place = 3,
    Use = 4,
    Activate = 5,
}

impl InteractAction {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::StartDigging),
            1 => Some(Self::StopDigging),
            2 => Some(Self::DiggingCompleted),
            3 => Some(Self::Place),
            4 => Some(Self::Use),
            5 => Some(Self::Activate),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::StartDigging => "INTERACT_START_DIGGING",
            Self::StopDigging => "INTERACT_STOP_DIGGING",
            Self::DiggingCompleted => "INTERACT_DIGGING_COMPLETED",
            Self::Place => "INTERACT_PLACE",
            Self::Use => "INTERACT_USE",
            Self::Activate => "INTERACT_ACTIVATE",
        }
    }
}

/// Mod channel signal types sent in `TOCLIENT_MODCHANNEL_SIGNAL`.
///
/// Direct port of the C++ `ModChannelSignal` enum in `src/modchannels.h`.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModChannelSignal {
    JoinOk = 0,
    JoinFailure = 1,
    LeaveOk = 2,
    LeaveFailure = 3,
    ChannelNotRegistered = 4,
    SetState = 5,
}

impl ModChannelSignal {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::JoinOk),
            1 => Some(Self::JoinFailure),
            2 => Some(Self::LeaveOk),
            3 => Some(Self::LeaveFailure),
            4 => Some(Self::ChannelNotRegistered),
            5 => Some(Self::SetState),
            _ => None,
        }
    }
}

/// Per-player dynamic information (display size, scaling, etc.) sent by
/// the client in `TOSERVER_UPDATE_CLIENT_INFO`.
///
/// Direct port of `ClientDynamicInfo` from
/// `src/client/clientdynamicinfo.h`.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct ClientDynamicInfo {
    pub render_target_size: (i32, i32),
    pub real_gui_scaling: f32,
    pub real_hud_scaling: f32,
    pub max_fs_size: (i32, i32),
    /// Added in 5.9.0. `false` on older clients.
    pub touch_controls: bool,
}
