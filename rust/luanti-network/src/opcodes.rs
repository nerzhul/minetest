// Opcodes and command definitions for the Luanti protocol
// Based on ToServerCommand and ToClientCommand enums

use std::fmt;

/// Commands that can be sent from client to server
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

    pub fn name(&self) -> &'static str {
        match self {
            Self::Init => "TOSERVER_INIT",
            Self::Init2 => "TOSERVER_INIT2",
            Self::ModChannelJoin => "TOSERVER_MODCHANNEL_JOIN",
            Self::ModChannelLeave => "TOSERVER_MODCHANNEL_LEAVE",
            Self::ModChannelMsg => "TOSERVER_MODCHANNEL_MSG",
            Self::PlayerPos => "TOSERVER_PLAYERPOS",
            Self::GotBlocks => "TOSERVER_GOTBLOCKS",
            Self::DeletedBlocks => "TOSERVER_DELETEDBLOCKS",
            Self::InventoryAction => "TOSERVER_INVENTORY_ACTION",
            Self::ChatMessage => "TOSERVER_CHAT_MESSAGE",
            Self::Damage => "TOSERVER_DAMAGE",
            Self::PlayerItem => "TOSERVER_PLAYERITEM",
            Self::RespawnLegacy => "TOSERVER_RESPAWN_LEGACY",
            Self::Interact => "TOSERVER_INTERACT",
            Self::RemovedSounds => "TOSERVER_REMOVED_SOUNDS",
            Self::NodeMetaFields => "TOSERVER_NODEMETA_FIELDS",
            Self::InventoryFields => "TOSERVER_INVENTORY_FIELDS",
            Self::RequestMedia => "TOSERVER_REQUEST_MEDIA",
            Self::HaveMedia => "TOSERVER_HAVE_MEDIA",
            Self::ClientReady => "TOSERVER_CLIENT_READY",
            Self::FirstSrp => "TOSERVER_FIRST_SRP",
            Self::SrpBytesA => "TOSERVER_SRP_BYTES_A",
            Self::SrpBytesM => "TOSERVER_SRP_BYTES_M",
            Self::UpdateClientInfo => "TOSERVER_UPDATE_CLIENT_INFO",
        }
    }

    /// Returns the required connection state for this command
    pub fn required_state(&self) -> ToServerConnectionState {
        match self {
            Self::Init => ToServerConnectionState::NotConnected,
            Self::FirstSrp | Self::SrpBytesA | Self::SrpBytesM | Self::Init2 => {
                ToServerConnectionState::Startup
            }
            _ => ToServerConnectionState::Ingame,
        }
    }
}

impl fmt::Display for ToServerCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Commands that can be sent from server to client
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
}

impl ToClientCommand {
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
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Hello => "TOCLIENT_HELLO",
            Self::AuthAccept => "TOCLIENT_AUTH_ACCEPT",
            Self::AcceptSudoMode => "TOCLIENT_ACCEPT_SUDO_MODE",
            Self::DenySudoMode => "TOCLIENT_DENY_SUDO_MODE",
            Self::AccessDenied => "TOCLIENT_ACCESS_DENIED",
            Self::BlockData => "TOCLIENT_BLOCKDATA",
            Self::AddNode => "TOCLIENT_ADDNODE",
            Self::RemoveNode => "TOCLIENT_REMOVENODE",
            Self::Inventory => "TOCLIENT_INVENTORY",
            Self::TimeOfDay => "TOCLIENT_TIME_OF_DAY",
            Self::CsmRestrictionFlags => "TOCLIENT_CSM_RESTRICTION_FLAGS",
            Self::PlayerSpeed => "TOCLIENT_PLAYER_SPEED",
            Self::MediaPush => "TOCLIENT_MEDIA_PUSH",
            Self::ChatMessage => "TOCLIENT_CHAT_MESSAGE",
            Self::ActiveObjectRemoveAdd => "TOCLIENT_ACTIVE_OBJECT_REMOVE_ADD",
            Self::ActiveObjectMessages => "TOCLIENT_ACTIVE_OBJECT_MESSAGES",
            Self::Hp => "TOCLIENT_HP",
            Self::MovePlayer => "TOCLIENT_MOVE_PLAYER",
            Self::AccessDeniedLegacy => "TOCLIENT_ACCESS_DENIED_LEGACY",
            Self::Fov => "TOCLIENT_FOV",
            Self::DeathScreenLegacy => "TOCLIENT_DEATHSCREEN_LEGACY",
            Self::Media => "TOCLIENT_MEDIA",
            Self::NodeDef => "TOCLIENT_NODEDEF",
            Self::AnnounceMedia => "TOCLIENT_ANNOUNCE_MEDIA",
            Self::ItemDef => "TOCLIENT_ITEMDEF",
            Self::PlaySound => "TOCLIENT_PLAY_SOUND",
            Self::StopSound => "TOCLIENT_STOP_SOUND",
            Self::Privileges => "TOCLIENT_PRIVILEGES",
            Self::InventoryFormspec => "TOCLIENT_INVENTORY_FORMSPEC",
            Self::DetachedInventory => "TOCLIENT_DETACHED_INVENTORY",
            Self::ShowFormspec => "TOCLIENT_SHOW_FORMSPEC",
            Self::Movement => "TOCLIENT_MOVEMENT",
            Self::SpawnParticle => "TOCLIENT_SPAWN_PARTICLE",
            Self::AddParticleSpawner => "TOCLIENT_ADD_PARTICLESPAWNER",
            Self::Camera => "TOCLIENT_CAMERA",
            Self::HudAdd => "TOCLIENT_HUDADD",
            Self::HudRm => "TOCLIENT_HUDRM",
            Self::HudChange => "TOCLIENT_HUDCHANGE",
            Self::HudSetFlags => "TOCLIENT_HUD_SET_FLAGS",
            Self::HudSetParam => "TOCLIENT_HUD_SET_PARAM",
            Self::Breath => "TOCLIENT_BREATH",
            Self::SetSky => "TOCLIENT_SET_SKY",
        }
    }

    /// Returns the channel this command should be sent on
    pub fn channel(&self) -> u8 {
        match self {
            Self::BlockData | Self::AddNode | Self::RemoveNode => 2,
            Self::ActiveObjectRemoveAdd | Self::ActiveObjectMessages => 1,
            _ => 0,
        }
    }

    /// Returns whether this command should be sent reliably
    pub fn is_reliable(&self) -> bool {
        match self {
            Self::BlockData => false, // Block data can be re-requested
            _ => true,
        }
    }
}

impl fmt::Display for ToClientCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Connection state for server processing client commands
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToServerConnectionState {
    NotConnected,
    Startup,
    Ingame,
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
