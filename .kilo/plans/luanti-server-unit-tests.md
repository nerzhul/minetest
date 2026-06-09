# Plan: Strengthen C++ Unit Test Coverage for the Luanti Server

## 1. Context

Luanti ships with a unit test harness under `src/unittest/`, built on a mix of
Catch2 (`src/catch.h`) and a small home-grown framework (`TestBase` /
`TestManager`) that is statically instantiated by the `test_*.cpp` files. The
test runner is `run_tests()` in `src/unittest/test.cpp:207`, triggered by the
CLI option `--run-unittests` (`src/main.cpp`).

This plan aims to **identify areas of the server-side C++ code that are
weakly or not covered at all** and to propose **new test files** (or new
methods to add to existing test files) to stabilise the code.

## 2. Current state (what is already tested)

`src/unittest/CMakeLists.txt:3-51` lists every existing test module:

| Module file | Covered class / area |
|---|---|
| `test_address.cpp` | `network::Address` (IPv4/IPv6, Resolve, serializeString) |
| `test_authdatabase.cpp` | Auth DB (backends) |
| `test_activeobject.cpp` | `ActiveObject` base |
| `test_areastore.cpp` | `AreaStore` (Lua + BTree) |
| `test_ban.cpp` | `BanManager` (basic CRUD) |
| `test_collision.cpp` | AABB / moving collisions |
| `test_compression.cpp` | `compression` |
| `test_connection.cpp` | `con::Connection` (partial) |
| `test_craft.cpp` | `CraftDefinition` |
| `test_datastructures.cpp` | home-grown containers |
| `test_filesys.cpp` | `fs::*` (paths, write, delete…) |
| `test_inventory.cpp` | `Inventory` / `ItemStack` |
| `test_irrptr.cpp` | Irrlicht smart-ptr helpers |
| `test_logging.cpp` | `log` |
| `test_lbmmanager.cpp` | `LBMManager` |
| `test_lua.cpp` | base Lua API |
| `test_map.cpp` | `Map` (via DummyMap) |
| `test_mapblock.cpp` | `MapBlock` |
| `test_mapdatabase.cpp` | map DB backends |
| `test_mapgen.cpp` | mapgen |
| `test_map_settings_manager.cpp` | `MapSettingsManager` |
| `test_mapnode.cpp` | `MapNode` |
| `test_modchannels.cpp` | `ModChannelMgr` (join/leave/send) |
| `test_modstoragedatabase.cpp` | mod storage DB |
| `test_moveaction.cpp` | rollback `MoveAction` |
| `test_noderesolver.cpp` | `NodeDefResolver` |
| `test_noise.cpp` | `Noise` |
| `test_objdef.cpp` | `ObjDefManager` |
| `test_profiler.cpp` | `Profiler` |
| `test_random.cpp` | `Random` / `PseudoRandom` |
| `test_sao.cpp` | `LuaEntitySAO` (added 2024, static/active) |
| `test_schematic.cpp` | `Schematic` |
| `test_scriptapi.cpp` | Lua scripting |
| `test_serialization.cpp` | `deSerializeString` etc. |
| `test_server_shutdown_state.cpp` | `Server::ShutdownState` (timer) |
| `test_servermodmanager.cpp` | `ServerModManager` |
| `test_settings.cpp` | `Settings` (parser, serialisation) |
| `test_socket.cpp` | UDP `Socket` |
| `test_srp_auth.cpp` | SRP authentication |
| `test_threading.cpp` | `Thread`, mutexes |
| `test_utilities.cpp` | `util/` helpers |
| `test_voxelarea.cpp` | `VoxelArea` |
| `test_voxelalgorithms.cpp` | `voxel::Algo` |
| `test_voxelmanipulator.cpp` | `VoxelManipulator` |
| `test_gettext.cpp` | i18n |
| `test_serveractiveobjectmgr.cpp` (in `src/test/`) | SAO mgr |
| `test_content_mapblock.cpp` (client) | client-side serialisation |
| `test_eventmanager.cpp` (client) | client event manager |
| `test_gameui.cpp` (client) | game UI |
| `test_keycode.cpp` (client) | keycodes |
| `test_mesh_compare.cpp` (client) | mesh helpers |
| `test_clientactiveobjectmgr.cpp` (client) | client-side AO mgr |

**Existing test helpers**: `mock_server.h`, `mock_inventorymanager.h`,
`mock_serveractiveobject.h`, `mock_activeobject.h`, `mesh_compare.{h,cpp}`,
`dummygamedef.h`, `dummymap.h`.

## 3. Server areas with weak or no coverage

After reading the headers (.h) and .cpp under `src/server/`, `src/network/`,
`src/database/` and `src/script/cpp_api/`, the following gaps appear, ranked
by priority.

### 3.1 High priority — high regression risk, sensitive code

1. **`RemoteClient` (and `ClientInterface`) — `src/server/clientiface.{h,cpp}`**
   No direct test. The `ClientState` state machine (CS_Created → CS_HelloSent
   → CS_AwaitingInit2 → CS_InitDone → CS_DefinitionsSent → CS_Active →
   CS_SudoMode → CS_Disconnecting) and the block-sending queues
   (`m_blocks_sent`, `m_blocks_sending`, `m_blocks_occ`, `m_media_sent`,
   `m_excess_gotblocks`) drive security- and bandwidth-critical behaviour.
   `IConnection` is a real dependency, but several methods can be tested on
   a bare `RemoteClient`:
   - `RemoteClient::markMediaSent` (deduplication)
   - `RemoteClient::setVersionInfo` / `getMajor/getMinor/getPatch/getFullVer`
   - `RemoteClient::setLangCode` / `getLangCode`
   - `RemoteClient::setDynamicInfo` / `getDynamicInfo`
   - `RemoteClient::setCachedAddress` / `getAddress`
   - `RemoteClient::uptime()`
   - `RemoteClient::resetChosenMech()` + `isMechAllowed()`
   - `RemoteClient::SetBlockNotSent` / `SetBlocksNotSent` / `GotBlock` /
     `SentBlock` / `isBlockSent` (pure set logic)
   - `ClientInterface::state2Name()` (used in logging)
   - `ClientInterface::getClientIDs()` with a mocked `IConnection`
     (see `con::IConnection` in `src/network/connection.h:73`).

2. **`PlayerSAO` — `src/server/player_sao.{h,cpp}`**
   Not tested. Very large (308 header lines). Areas testable in isolation:
   - `LagPool` (struct exposed in `player_sao.h:20`): `setMax`, `add`,
     `empty`, `grab` — already dependency-free, trivial tests.
   - `PlayerHPChangeReason::setTypeFromString` / `getTypeAsString`
     (`player_sao.h:259-299`): full coverage of the 7 types.
   - Player property serialisation/loading (`getStaticData`,
     `getClientInitializationData`, `getPropertyPacket`): feasible with
     `MockServer` + `ServerEnvironment` (see the pattern in `test_sao.cpp`
     that already drives `LuaEntitySAO`).
   - `noCheatDigStart` / `End` / `getNoCheatDigPos` / `getNoCheatDigTime`
   - `setMaxSpeedOverride` + impact on `checkMovementCheat` (mocking
     `RemotePlayer`)

3. **`UnitSAO` — `src/server/unit_sao.{h,cpp}`** (405 lines)
   No direct test. Handles LuaEntity serialisation and property
   application. Reusable to test:
   - `getStaticData` round-trip via a mocked `Server::m_script`
   - Correct application of `ObjectProperties` (initial HP, nametag text,
     point-of-view, armour…).

4. **`serverpackethandler.cpp` / `clientpackethandler.cpp`**
   (1920 + 1839 lines) — very large, state/anti-cheat, but depend on a
   full `Server`. Tests only feasible with an end-to-end harness, out of
   scope for "simple" unit tests. **Excluded** from this first wave.

5. **`Connection` (`src/network/connection.{h,cpp}`) — 17 lines .cpp**
   The implementation is almost entirely in the header (`inline`). The
   existing `test_connection.cpp` covers some paths. Gaps:
   - Channel allocation / reuse (ID numbers, reliability, fragmentation
     and reassembly)
   - `putCommand`/`getCommand` behaviour when the buffer is full
   - `Abort`/`Reset` behaviour on the ID sequence
   - `Peer` behaviour when an `incoming` packet has an unknown channel

### 3.2 Medium priority — subtle bugs, business logic

6. **`network::Address` — `src/network/address.{h,cpp}`**
   The existing test (`test_address.cpp`) covers `isLocalhost`,
   `serializeString` and `Resolve("localhost")`. Gaps:
   - `Address::operator==` / `!=` (different families, same octets)
   - `Address::print(std::ostream&)` (used in logging)
   - `Resolve()` with a non-existent name: must throw `ResolveError`
   - `Resolve()` with a raw numeric IPv4 (e.g. `"8.8.8.8"`): must work
     without DNS and yield `AF_INET`
   - `Resolve()` with a bracketed IPv6 `"[::1]"` (used in `minetest.conf`)
   - `setAddress(u32)`, `setAddress(u8,u8,u8,u8)`,
     `setAddress(IPv6)`, `setPort(u16)` setters

7. **`BanManager` — `src/server/ban.{h,cpp}`**
   `test_ban.cpp` covers: create, add, remove (by IP and by name),
   modification flag, getBanName, getBanDescription. Gaps:
   - `load()`: load a pre-existing file (create a file with 2-3 entries,
     reload via a second `BanManager`, verify `getBanName` /
     `isIpBanned` are correct and that `isModified()` is `false`
     immediately after load)
   - Round-trip persistence: `add` + destruction (which calls `save()`)
     + construction of a new `BanManager` on the same file, verify the
     bans are still present
   - `getBanDescription("")` must return **all** bans separated by
     `, `. The current test only uses one entry — test with 0, 1 and
     several.
   - Field trimming: `load()` does `trim(f.next("|"))` — test with
     spaces around the fields.

8. **`ModChannelMgr` — `src/modchannels.{h,cpp}`**
   `test_modchannels.cpp` covers join/leave/send via the gamedef.
   Gaps:
   - `ModChannel::registerChannel`: a channel joined once returns
     `false` on the second attempt (already registered)
   - `ModChannel::leaveChannel` on a never-joined channel returns
     `false`
   - `broadcast` to multiple peers (two peers joined on the same
     channel, a message must be delivered to both, and the sender is
     excluded if present in the list)
   - `ModChannel` persistence (serialise to / from `std::string`)
   - `getChannel` returns `nullptr` for an unknown name

9. **`ServerModManager` — `src/server/mods.{h,cpp}`**
   Coverage is solid. Remaining gaps:
   - `getModsMediaPaths`: expected ordering (game path before mod path);
     the existing `testGetModMediaPaths` could be tightened (the API
     comment says "files from an earlier path should not be replaced
     by files from a latter one").
   - `loadMods(ServerScripting&)`: verify actual registration in the
     scripting layer (needs `MockServer` + `createScripting()`).

10. **`Server::ShutdownState` — `src/server.h`**
    `test_server_shutdown_state.cpp` is complete and well done. Nothing
    important is missing, except maybe testing `reset()` after a
    `trigger()`.

### 3.3 Low priority — utilities, low regression risk

11. **`network::NetworkPacket` (`src/network/networkpacket.{h,cpp}`,
    524 lines)** — not tested directly. Possible gaps:
    - `put`/`get` for all primitive types (u8, u16, u32, u64, s16, s32,
      s64, f32, f64, v2f, v3f, v2s16, v3s16, v2s32, v3s32, string, raw)
    - `readU24` / `putU24` (used for the voice chunk size in the
      protocol)
    - `checkReadBuffer` behaviour when too many bytes are read

12. **`LBMManager` — partially tested.** Also check the trigger path
    when `NodeDefManager` versions change.

13. **`Settings` — well covered**, but we can add:
    - `getFlag`, `setFlag`, `removeFlag` (used in minetest.conf.example)
    - `getEntry` returns the position in the group table
    - Behaviour on a >1 GB config file (memory bounded)

14. **`util/pointedthing`, `util/directiontables`, `util/serialize`** —
    already strong coverage. Could add ABI / alignment tests.

15. **`database/*` (`src/database/`)** — `test_mapdatabase.cpp` /
    `test_modstoragedatabase.cpp` / `test_authdatabase.cpp` exist. Gap:
    no direct test of the **dummy** database (`database-dummy.{h,cpp}`)
    used in tests. Likewise, `database-files` has no dedicated test
    (only used indirectly). Propose `test_database_files.cpp`.

## 4. Proposed new test files

Based on the analysis above, here are the files to create. Each follows the
convention of `test_*.cpp` (inherit from `TestBase`,
`TestManager::registerTestModule` in the static constructor, `testXxx`
methods in lowercase, `TEST(...)` macro).

### 4.1 `src/unittest/test_lagpool.cpp` (high priority, small)

- Pure tests on the `LagPool` struct exposed in `player_sao.h:20`:
  - Initial state: `m_pool = m_max = 15.0f`
  - `setMax(10)` when pool=15: pool must become 10
  - `add(5)`: pool -= 5
  - `add(20)`: pool = 0 (clamp)
  - `empty()`: pool = max
  - `grab(0)` returns `true` even when full
  - `grab(dtime > m_max)` returns `false`
  - `grab(5)` when pool=3 and max=15: pool becomes 8, returns `true`
  - Combined add/grab/add sequence to check the invariant
    `0 <= pool <= max`

### 4.2 `src/unittest/test_remoteclient.cpp` (high priority)

Target: `src/server/clientiface.h` (the `RemoteClient` class).

- `testVersionInfo`: `setVersionInfo(5,6,7,"5.6.7-dev")` → getters
- `testLangCode`: set/get + Unicode values
- `testCachedAddress`: set/get, copy
- `testDynamicInfo`: set/get round-trip on `ClientDynamicInfo`
- `testMediaSentDedup`: `markMediaSent("foo")` twice → second call
  returns `false` (already present)
- `testMediaSentUnique`: first call returns `true`
- `testBlockSentLifecycle`: `isBlockSent(p)` is false by default,
  `GotBlock(p)` does NOT mark as sent (see the code), `SentBlock(p)`
  does. `SetBlockNotSent(p)` clears it. `isBlockSent` after this
  sequence is false.
- `testBlockSendingLimit`: fill `m_blocks_sending` up to
  `m_max_simul_sends` (default 10) and verify `getSendingCount()`.
- `testStateTransitions`: `notifyEvent(CSE_Hello)` should move to
  `CS_HelloSent`, etc. (all 8 transitions)
- `testResetChosenMech`: `resetChosenMech` resets to
  `AUTH_MECHANISM_NONE` and `auth_data = nullptr`
- `testIsMechAllowed`: bit masking
- `testUptimeMonotonic`: `uptime()` increases after sleep

### 4.3 `src/unittest/test_clientstate.cpp` (high priority, small)

Target: `ClientInterface::state2Name()` (`clientiface.cpp`) and the
enum values.

- Cover all 10 `ClientState` values
- Verify that a change in the enum breaks the test (a static counter
  via `sizeof(statenames)/sizeof(...)`)
- Verify that no returned name is `nullptr` or empty

### 4.4 `src/unittest/test_player_hp_change_reason.cpp` (high priority, small)

Target: `struct PlayerHPChangeReason` in `player_sao.h:234`.

- `setTypeFromString`: all 7 valid types + an invalid one
  (`"unknown"` → false, type unchanged)
- `getTypeAsString`: all 7 types + 1 unknown
- Round-trip consistency: `setTypeFromString` then `getTypeAsString`
  gives back the original name (except `SET_HP_MAX` which is exposed
  as `set_hp`)
- `hasLuaReference`: false by default, true after `lua_reference = 5`
- 1, 2 and 3-arg constructors: field population

### 4.5 `src/unittest/test_address_extended.cpp` (medium priority)

Target: `Address` (`src/network/address.h`).

- `testEquality`: same IPv4 ==, IPv4 != IPv6
- `testPrint`: `print(std::ostringstream)` produces the same string as
  `serializeString()`
- `testSetAddress*`: all setters
- `testResolveNumericIPv4`: `Resolve("8.8.8.8")` must yield `AF_INET`
  and `getAddress().s_addr == 0x08080808`
- `testResolveNumericIPv6`: `Resolve("::1")` must yield `AF_INET6`
- `testResolveBracketedIPv6`: `Resolve("[::1]")` (used in
  `minetest.conf.example` `bind_address = [::]`)
- `testResolveInvalid`: `Resolve("this.host.does.not.invalid")` must
  throw `ResolveError`
- `testResolveEmpty`: `Resolve("")` resets to `isAny()`

### 4.6 `src/unittest/test_modchannels_extended.cpp` (medium priority)

Target: `src/modchannels.{h,cpp}` directly (no gamedef).

- `testChannelRegistry`: `registerChannel` once then again → false
- `testLeaveUnregistered`: `leaveChannel` on an unknown name → false
- `testBroadcast`: create a `ModChannelMgr`, register a channel with
  2 peer IDs, call `broadcast`, verify that both peers receive, and
  that the sender is excluded
- `testGetChannelNull`: `getModChannel("unknown")` → nullptr
- `testSerialization`: `getChannel("foo")->serializeToString` then
  `unserializeChannel` returns an identical state

### 4.7 `src/unittest/test_ban_extended.cpp` (medium priority)

Target: `BanManager`.

- `testLoadExistingFile`: create a file with 3 bans, load via
  `BanManager`, verify `isIpBanned` / `getBanName` and that
  `isModified()` is `false` right after load
- `testPersistenceRoundTrip`: `bm1.add(...)`, destroy, `bm2` on the
  same file, verify bans are restored and `isModified()` is false
- `testGetBanDescriptionAll`: `getBanDescription("")` with 0, 1 and
  many bans — check the format `"ip|name, ip|name, "`
  (note: the code does `s.substr(0, s.size() - 2)` which produces
  `s[:-2]`; with 0 bans this is a visible bug: `s.size()=0` →
  `substr(0, -2)` throws `out_of_range` — should be fixed alongside
  the test)
- `testTrimWhitespace`: a file with `  1.2.3.4  |  alice  \n` should
  load as `1.2.3.4` / `alice`

### 4.8 `src/unittest/test_networkpacket.cpp` (medium priority)

Target: `src/network/networkpacket.{h,cpp}`.

For each type, put/get round-trip:
- `putU8` / `getU8`, `putU16` / `getU16` (little-endian), `putU32` /
  `getU32`, `putU64` / `getU64`
- `putS16` / `getS16`, etc.
- `putF32` / `getF32`, `putF64` / `getF64`
- `putV2F` / `getV2F`, `putV3F` / `getV3F`, `putV2S16` / `getV2S16`,
  `putV3S16` / `getV3S16`, `putV2S32`, `putV3S32`
- `putString` / `getString`, `putRawString`
- `putU24` / `readU24` (specific to voice packets)
- `checkReadBuffer` (reading past the end must throw `PacketError`)
- `m_read_offset` advances correctly after `getX`
- `<<` and `>>` operators for `std::string` and `Address`

### 4.9 `src/unittest/test_unit_sao.cpp` (medium priority)

Target: `src/server/unit_sao.{h,cpp}`. Reuses the `MockServer` +
`ServerEnvironment` pattern from `test_sao.cpp`.

- `testGetStaticData`: check that the returned string starts with
  `"return {"` (or the current format)
- `testSetProperties`: `setProperties({nametag="X", hp_max=42})` →
  `getHP() == 42`, `getName()` contains "X"
- `testPunchDecrementsHP`: `punch` from a `MockServerActiveObject`
  must decrement `m_hp` and the `m_hp` sent to the client

### 4.10 `src/unittest/test_servermodmanager_loadmods.cpp` (low priority)

- `testLoadMods`: load a mod via `loadMods`, verify
  `getModSpec("test_mod") != nullptr`
- `testGetModsMediaPathsOrder`: create a game with a textures folder
  and a mod with a textures folder; verify the game folder comes
  first
- `testGetModsMediaPathsEmpty`: no mods, no folder → empty or just
  the game path

### 4.11 `src/unittest/test_database_files.cpp` (low priority)

Target: `src/database/database-files.{h,cpp}`. Not directly tested
today.

- `testSaveLoadBlock`: put/get/has/delete on a minimal `MapBlock`
  (manual serialisation)
- `testSaveLoadPlayer`: same on `RemotePlayer`
- `testSaveLoadMetadata`: round-trip of `ServerMapMetaRef` or
  equivalent

## 5. Execution plan

1. **Discuss choices** with the user:
   - confirm the proposed implementation order
   - confirm whether a `Database` "files" backend test is needed
   - see whether the user prefers to start with stabilisation
     (`test_ban_extended.cpp` + `test_modchannels_extended.cpp` +
     `test_address_extended.cpp`), which are the fastest

2. **Phase 1 — quick wins** (1-2 days):
   `test_lagpool.cpp`, `test_player_hp_change_reason.cpp`,
   `test_clientstate.cpp`. No mocks, pure classes.

3. **Phase 2 — Network / ban coverage** (2-3 days):
   `test_address_extended.cpp`, `test_ban_extended.cpp`,
   `test_modchannels_extended.cpp`, `test_networkpacket.cpp`.

4. **Phase 3 — SAO / PlayerSAO** (3-4 days):
   `test_remoteclient.cpp`, `test_unit_sao.cpp`,
   and `test_player_hp_change_reason.cpp` enriched if needed.

5. **Phase 4 — Database and finish** (1-2 days):
   `test_database_files.cpp`, `test_servermodmanager_loadmods.cpp`.

6. **For each file**:
   - Create the `test_*.cpp`
   - Add its name to `src/unittest/CMakeLists.txt:3-51` (otherwise
     the test will not compile)
   - Compile + run via `./bin/luanti --run-unittests`
   - Verify the output: `TestBan`/`TestModChannels`/etc.

7. **Submit a local code review** via the skill
   `.kilo/local-review-uncommitted` (see the system rule on
   "Suggestions").

## 6. Success criteria

- All new tests pass
- No regression on the existing tests
- Each test has a unique `getName()` and is listed in the output of
  `./luanti --run-unittests`
- Each new test covers a behaviour documented in the corresponding
  header (no "magic" tests)

## 7. Out of scope (intentionally)

- Client/server integration tests (`test_*` end-to-end with a real
  `Server` started): too heavy, already partly covered by the Lua
  test framework
- Tests for `serverpackethandler.cpp` / `clientpackethandler.cpp`:
  need a full packet harness, to be discussed separately
- Performance / benchmark tests: `src/benchmark/` is a different
  domain

## 8. Open questions for the user

Before implementing, I'd like to ask 2 questions:

1. **Scope**: would you rather start with the quick wins
   (Phase 1, ~1-2 days, no mocks required) or go straight for
   `test_remoteclient.cpp`, which is the biggest confidence gain on
   the server side but requires more work?

2. **Bug found while reading**: in `BanManager::getBanDescription`
   (`ban.cpp:77-89`), when no ban matches, the code does
   `s = s.substr(0, s.size() - 2)` on an empty string, which throws
   `std::out_of_range`. Would you like to:
   (a) just add a test that documents the bug and fix it
   afterwards, or
   (b) let the test fail as a TODO for the moment?
