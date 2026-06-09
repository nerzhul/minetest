# Plan: Refactor Luanti server (src/) for modularity and testability

## 1. Diagnostic — current state of the server architecture

Inspecting the code (`src/server.h`, `src/server.cpp`, `src/serverenvironment.{h,cpp}`, `src/network/connection.h`, `src/network/serverpackethandler.cpp`, `src/network/serveropcodes.{h,cpp}`, `src/database/database.h`, `src/unittest/mock_server.h`) reveals several classic architectural "code smells":

| # | Problem | Concrete symptoms |
|---|---------|-------------------|
| 1 | **God class `Server`**: 828 lines in `.h`, 4543 in `.cpp`, **111 `Server::xxx` methods** (see grep), **~60 member attributes**, depends on nearly every subsystem. | Unit tests forced to subclass `Server` (`MockServer` at `src/unittest/mock_server.h:11`) and to mock the network layer by deleting `start()/stop()`. Tight coupling, fragile test base. |
| 2 | **Protocol ↔ business logic coupling**: `toServerCommandTable` (`src/network/serveropcodes.cpp:12`) stores **pointers to `Server` members**. The whole protocol "handler table" forces the inclusion of `server.h` (see comment `src/network/serveropcodes.h:11`). | The protocol cannot be tested or reused without instantiating a full `Server`; any change to the table requires touching the engine. |
| 3 | **Client/server asymmetry for the protocol**: the client table (`src/network/clientopcodes.cpp`) is cleaner (separates handler/reception), the server is everything inside `Server::*`. | Inconsistency; missed symmetry opportunities. |
| 4 | **Network ↔ engine coupling**: `Server::m_con` (raw `con::IConnection*`) directly owned; packet handlers (`serverpackethandler.cpp:36`+) mutate `Server` state en masse. | Impossible to test a handler in isolation or substitute a transport (websocket, webrtc, loopback for tests). |
| 5 | **`ServerEnvironment` coupled back to `Server`**: `m_server` (raw, non-owning) at `serverenvironment.h:370`, and methods like `getScriptIface()`/`getGameDef()` that make it dependent. The `//TODO find way to remove this fct!` (`serverenvironment.h:125`) says it. | Dependency loop; tests must build a full `Server` just to step the environment. |
| 6 | **No testable business abstractions**: no `IPlayerManager`, `IWorld`, `IAuthService`, `IBanService`, `IMediaService` interfaces. The code talks directly to `RemoteClient`, `PlayerSAO`, `BanManager`, etc. | Business logic (anti-cheat, kick, ban, spawn forms...) is not unit-testable. |
| 7 | **Persistence via `static open*Database` + `if/else` backend** in `Server` (see `src/server.cpp:64-70`, similar `createMTP` factory). | Backend-selection code is not injectable; tests forced to use SQLite3 or dummy. |
| 8 | **Global `g_settings` / `g_profiler`**: scattered static accesses in the server (`src/server.cpp:696`, etc.). | Not mockable, shared state between tests, ordering-dependent. |
| 9 | **No DI / composition root**: `Server::Server(...)` (see `src/server.cpp:283`) hard-constructs `m_itemdef`, `m_nodedef`, `m_craftdef`, `m_con`, `m_modchannel_mgr`…, no injection parameter. | Cannot substitute a service in test or "headless" mode. |
|10 | **Existing tests limited to "mock + override"**: `MockServer` must publicly inherit from `Server` (inheritance + virtual `SendChatMessage`); only `TestServerShutdownState` and `TestMoveAction` are `friend` of `Server` (`src/server.h:496-497`). | Discourages writing tests, leaks implementation through friendship. |
|11 | **Mixed responsibilities in `AsyncRunStep`** (`src/server.cpp:667`): env stepping, block sending, timers, metrics, shutdown, media, particles, masterserver… all inline. | Main loop not testable, hard to instrument/pause. |
|12 | **Lua/`<scripting_server>` coupled to business logic**: `Server` owns a `std::unique_ptr<ServerScripting>`, accessed from the packet handler. | Impossible to test a handler without a Lua environment. |

## 2. Goal

Break down the `Server` monolith into a small **orchestration core** + **injectable services** with clean boundaries, such that:
- services carry their own state and offer interfaces (C++20 inheritance / concepts);
- the protocol layer becomes a **pluggable adapter** (incoming port);
- the persistence layer goes through abstract factories;
- the majority of business rules become testable **without network, without Lua, without irrlicht**.

## 3. Target architecture

```
                       ┌──────────────────────────┐
                       │   Server (orchestrator)  │  ← loop, env, lifecycle
                       │   - composition root     │
                       │   - main step() loop     │
                       └──────────┬───────────────┘
                                  │ owns (unique_ptr)
        ┌─────────────────────────┼──────────────────────────┐
        ▼                         ▼                          ▼
┌──────────────┐         ┌────────────────┐         ┌────────────────┐
│ IWorldSrv    │         │ INetServer     │         │ IPlayerSvc     │
│ (env+map+    │         │ (incoming port │         │ (sess, kick,   │
│  scripting)  │         │  protocol)     │         │  privs, forms) │
└──────┬───────┘         └────────┬───────┘         └────────┬───────┘
       │                          │                          │
       ▼                          ▼                          ▼
   ServerEnvironment        ServerNetworkAdapter        IPlayerSvc impl
   (no m_server)            (handler table)             (can be mocked)
                                  │
                                  ▼
                          ITransport (con::IConnection)
                          (already abstract, isolate better)
```

### 3.1 Proposed functional split

| New component | Role | Current source concerned | Testable? |
|---|---|---|---|
| `IServerServices` (facade) | Regroups services exposed to handlers: `IPlayerSvc`, `IWorldSrv`, `IAuthorizationService`, `IMediaService`, `IMetricsService`, `INotificationService`. | `Server` (API methods) | Yes (mocks) |
| `PlayerService` (impl) | HUD, eye/sky/sun/moon/stars/clouds, fov, hotbar, animations, formspec state, kick, peer info. | `Server::kickAllPlayers`, `hud*`, `setSky*`, `SendPlayerHP`, etc. | Yes, injecting a `RemotePlayer` and a fake `INetSender`. |
| `WorldService` (impl) | Environment step, block sending, ABM/LBM, particles, modchannels, time-of-day. | `Server::AsyncRunStep`, `SendBlocks`, `SendSpawnParticles`, `ServerEnvironment::step`. | Yes, injecting a test `ServerEnvironment`. |
| **`IAuthorizationService`** (consolidated) | **Single answer to "who is allowed to do what?"** — covers: ban list (IP/name), SRP authentication handshake + state, privilege lookup, sudo mode. See §11 below. | `Server::BanManager` + `Server::acceptAuth` + `Server::denyIfBanned` + `Server::getPlayerEffectivePrivs` + `Server::checkPriv` + `Server::setIpBanned`/`unsetIpBanned` + `Server::handleCommand_FirstSrp/SrpBytesA/SrpBytesM`. | Yes, mocking `IAuthDatabase` + an in-memory ban list. |
| `MediaService` | Media list, sha1 cache, announce/send/dynamic. | `Server::fillMediaCache`, `sendMediaAnnouncement`, `sendRequestedMedia`, `stepPendingDynMediaCallbacks`, `addMediaFile`, `dynamicAddMedia`. | Yes. |
| `NotificationService` | `printToConsoleOnly`, notify, broadcast chat. | `Server::printToConsoleOnly`, `notifyPlayers`. | Yes. |
| `NetworkAdapter` (incoming port) | `void dispatch(session_t, NetworkPacket&)`; contains the `unordered_map<Opcode, HandlerFn>`; `HandlerFn` = `std::function<...>` capturing an `IServerServices&` instead of a `Server*`. | `src/network/serveropcodes.cpp` + `serverpackethandler.cpp` | Yes (synthetic packets). |
| `ServerNetworkAdapter` (impl) | Reads from `con::IConnection`, dispatches. | `Server::Receive`, `ProcessData`, `toServerCommandTable`. | Yes, with a mocked `IConnection` (already feasible: `TestConnection`). |
| `Transport` (already `con::IConnection`) | Formally unchanged, but injected via the constructor instead of hard `createMTP`. | `Server::Server` line ~297 | Yes. |
| `DatabaseFactory` (outgoing port) | `IDatabaseFactory` interface with `openMapDb`, `openPlayerDb`, `openAuthDb`, `openModStorageDb`; impls `SqliteDatabaseFactory`, `FilesDatabaseFactory`, etc. | `ServerEnvironment::openPlayerDatabase/openAuthDatabase`, `Server::openModStorageDatabase` | Yes. |
| `Settings` provider | `ISettingsProvider` (thread-safe facade over `Settings`). | scattered `g_settings` access | Yes. |
| `MetricsService` | Thin facade over `MetricsBackend`. | `MetricCounterPtr/GaugePtr` as `Server` members | Yes (Prometheus or dummy). |
| `RollbackService` | `rollbackRevertActions`, Lua hook. | `Server::rollbackRevertActions` + `m_rollback`. | Yes. |
| `ModChannelService` | `join/leave/send/broadcast/getModChannel`. | `Server::joinModChannel` etc. | Yes. |
| `ShutdownController` | The internal `ShutdownState` extracted into a standalone class. | `Server::ShutdownState` (nested) | **Already testable** (`TestServerShutdownState`), but hardened by being externalized. |

### 3.2 Server becomes a thin orchestrator

```cpp
// src/server.h (sketch)
class Server : public con::PeerHandler, public MapEventReceiver, public IGameDef {
public:
    // Composition root: injection of all dependencies.
    struct Dependencies {
        std::unique_ptr<ITransportFactory> transport;     // creates IConnection
        std::unique_ptr<IDatabaseFactory>  databases;
        std::unique_ptr<ISettingsProvider> settings;
        std::unique_ptr<IMetricsBackend>    metrics;
        std::unique_ptr<ServerEnvironment>  env;          // owns map+scripting
        std::unique_ptr<ServerScripting>    scripting;    // can be null in tests
        std::unique_ptr<INetworkAdapter>    net_adapter;  // protocol dispatch
        // ... services ...
    };

    Server(Dependencies deps, GameContext ctx);
    ~Server();

    // The public API is now only a proxy to services.
    IPlayerSvc    &players()    { return *m_deps.players; }
    IWorldSvc     &world()      { return *m_deps.env ? static_cast<IWorldSvc&>(*m_deps.env) : *m_fake_world; }
    IAuthService  &auth()       { return *m_deps.auth; }
    IBanService   &bans()       { return *m_deps.bans; }
    // ...

    // IGameDef facade: delegations.
    IItemDefManager* getItemDefManager() override;

private:
    Dependencies m_deps;
    ShutdownController m_shutdown;
    // No more 60 attributes: everything is in services.
};
```

`AsyncRunStep` shrinks to:

```cpp
void Server::AsyncRunStep(float dtime, bool initial) {
    if (m_shutdown.isFailing()) return;
    m_net_adapter->flushOutgoing(dtime);              // SendBlocks, particles, media callbacks
    if (dtime == 0 && !initial) return;
    m_metrics->incUptime(dtime);
    m_shutdown.tick(dtime);
    {
        EnvAutoLock lock(this);
        m_deps.env->step(dtime);
    }
    m_world_service->runPeriodicJobs(dtime);            // map save, masterserver, modstorage, liquid transform
    m_media_service->tick(dtime);
}
```

### 3.3 Protocol layer: `Opcode → std::function` table

```cpp
// src/network/server_dispatcher.h
using PacketHandler = std::function<void(
        IServerServices& services,
        INetSender& sender,
        session_t peer_id,
        NetworkPacket& pkt)>;

class ServerDispatcher {
public:
    void registerHandler(u16 opcode, ToServerConnectionState state, PacketHandler h);
    void dispatch(IServerServices&, INetSender&, NetworkPacket& pkt) const;
private:
    struct Entry { ToServerConnectionState state; PacketHandler fn; };
    std::unordered_map<u16, Entry> m_table;   // goodbye pointers array!
};
```

* Remove coupling `void (Server::*handler)(NetworkPacket*)`.
* `INetSender` (new small interface: `Send(NetworkPacket&)`, `Broadcast`, `Disconnect(session_t)`) is implemented by an adapter that owns a `con::IConnection&` (mutex taken internally). Handlers receive `INetSender&` instead of `Server&`, hence testable with a `MockNetSender`.
* The `Opcode` constant array can be replaced by `std::array<Entry, TOSERVER_NUM_MSG_TYPES>` (upward compatible) or `unordered_map` (denser).

### 3.4 ServerEnvironment freed from Server

* `m_server` (raw ptr) → replaced by injection of `IBanService*`, `IAuthService*`, `INetSender*` or better: removed entirely. The `// TODO find way to remove this fct!` (`serverenvironment.h:125`) is resolved by exposing these hooks via a `WorldHooks` interface passed to `ServerEnvironment`.
* `getScriptIface()` exposed via `IScriptingHost` (`SAO`s only depend on the interface).
* `getGameDef()` removed; replaced by typed accessors.

### 3.5 Persistence: abstract factory

```cpp
class IDatabaseFactory {
public:
    virtual ~IDatabaseFactory() = default;
    virtual std::unique_ptr<MapDatabase> openMap(const std::string &world_path, const Settings &) = 0;
    virtual std::unique_ptr<PlayerDatabase> openPlayers(const std::string &world_path, const Settings &) = 0;
    virtual std::unique_ptr<AuthDatabase> openAuth(const std::string &world_path, const Settings &) = 0;
    virtual std::unique_ptr<ModStorageDatabase> openModStorage(const std::string &world_path, const Settings &) = 0;
};

class BuiltinDatabaseFactory : public IDatabaseFactory { /* current logic */ };
class InMemoryDatabaseFactory : public IDatabaseFactory { /* for tests: returns in-memory impls */ };
```

Advantage: all environment tests (`test_serveractiveobjectmgr`, `test_authdatabase`, `test_modstoragedatabase`, `test_moveaction`, `test_sao`, `test_server_shutdown_state`, `test_scriptapi`) can share an in-memory factory.

### 3.6 Settings and globals

* Introduce `ISettingsProvider` (thread-safe facade).
* `Server` receives an `ISettingsProvider&` instead of accessing `g_settings`.
* Eventually, keep `g_settings` only as a default wrapper resolving to `ISettingsProvider`.
* Same for `g_profiler` (can be injected; defaults to the global `g_profiler`).

### 3.7 Tests: new harness

* `TestServer` no longer inherits from `Server`; it **builds a `Server` with test `Dependencies`** (mock `MockTransport` transport, in-memory BD factory, minimal scripting, `MockNetSender`).
* Packet handlers become testable by building a serialized `NetworkPacket`, calling `ServerDispatcher::dispatch(services, sender, pkt)`, and asserting on the `MockNetSender`.
* `Server` `friend`s (`TestServerShutdownState`, `TestMoveAction`) are eliminated: `ShutdownController` is directly instantiable.

## 4. Execution plan (incremental, each step backward-compatible)

### Step 0 — Preparation (half a day)
* Add `src/server/services/` (new folder).
* Add `src/network/server_dispatcher.h/.cpp`.
* Establish the interfaces in `src/server/services/iservices.h` (all `IService`: pure virtual `name()` for debug, methods per responsibility).
* CMake: new subfolder.

### Step 1 — Extract `ShutdownController` (1 day)
* Move `Server::ShutdownState` to `src/server/shutdown_controller.{h,cpp}`; self-sufficient (it only depends on `Server` for `SendChatMessage` → inject `INotificationService*`).
* Adapt `TestServerShutdownState` (becomes trivial, no more `friend`).
* ✅ Fully backward-compatible step (Friend becomes unnecessary but kept temporarily).

### Step 2 — Introduce `INetSender` and `ServerDispatcher` (2-3 days)
* Define `INetSender` (Send/Broadcast/Disconnect/GetAddress).
* Implement `ConnectionNetSender` that takes `con::IConnection&` and `PeerHandler` callbacks.
* Define `ServerDispatcher` with `std::function`-based handlers.
* Implement 1 "pilot" handler (e.g. `handleCommand_Null` + `handleCommand_Deprecated`) via the new API, wired in parallel during the transition.
* Tests: `unittest/test_server_dispatcher.cpp`.

### Step 3 — Migrate packet handlers one by one (1-2 weeks)
* Convert `handleCommand_*` one by one to `PacketHandler` capturing `IServerServices&` and `INetSender&`.
* At each conversion: replace `Server::foo()` with `services.foo()`.
* Keep `toServerCommandTable` pointing to `Server::*` but these become simple **shims**: `void Server::handleCommand_X(pkt) { m_dispatcher.dispatchX(m_services, m_net_sender, pkt->getPeerId(), *pkt); }`.
* Once all migrated, remove the legacy table and `server.h` is no longer included by `serveropcodes.h`.

### Step 4 — Extract services (2-3 weeks, in parallel with step 3)
* `MediaService` (most isolated): extraction of `fillMediaCache`, `addMediaFile`, `sendMediaAnnouncement`, `sendRequestedMedia`, `stepPendingDynMediaCallbacks`, `dynamicAddMedia`, `MediaInfo`. Dependencies: `ISettingsProvider`, `Map`, `INetSender`, `ServerScripting*` (for Lua hooks).
* `BanService`: extraction of `m_banmanager` + 4 methods.
* `AuthService`: extraction of `acceptAuth`, `DenyAccess`, `DenySudoAccess`, SRP handlers. Owns `IAuthDatabase*`.
* `NotificationService`: `printToConsoleOnly`, `notify*`, broadcast.
* `PlayerService` (the biggest): hp/breath, hud, sky/sun/moon/stars/clouds, fov, hotbar, eye offset, animations, formspec, privs, kick, ban, peer info. Dependencies: `ServerEnvironment`, `INetSender`, `IBanService`, `IAuthService`.
* `WorldService` (alias for the improved `ServerEnvironment`): step, blocks, particles, modchannels, rollback, time-of-day.

### Step 5 — Decouple `ServerEnvironment` from `Server` (1 week)
* Introduce `WorldHooks`: callbacks the env can call (instead of a `Server*`).
* `WorldHooks` is implemented by `Server` (facade) or by a `MockWorldHooks` in tests.
* Remove the `m_server` raw ptr and `getGameDef()`.

### Step 6 — `IDatabaseFactory` (3-4 days)
* Define interface + `BuiltinDatabaseFactory` (takes current logic) + `InMemoryDatabaseFactory` (for tests).
* Modify `ServerEnvironment` and `Server` to receive the factory.
* Wire in `Server::Server`.

### Step 7 — Composition root and injection in `Server` (3-4 days)
* Define `Server::Dependencies`.
* Keep a "legacy" constructor that builds the `Dependencies` by default (backward compat) and a "full DI" constructor for tests.
* Reduce `Server.h` to the orchestration facade.

### Step 8 — Cleanup and deprecations (1 week)
* Remove `friend class Test*` from `Server`.
* Remove `MockServer` (replaced by direct construction of `Server` with `Dependencies`).
* Document the new architecture in `doc/` (`doc/architecture.md` or `doc/server_architecture.md`).

### Step 9 — Tests for the new architecture (ongoing)
* `unittest/test_player_service.cpp` (privs, kick, formspec, hud).
* `unittest/test_auth_service.cpp` (SRP flow with in-memory IAuthDatabase).
* `unittest/test_ban_service.cpp`.
* `unittest/test_media_service.cpp`.
* `unittest/test_dispatcher.cpp` (all opcodes at least on "happy path" + states).
* `unittest/test_world_hooks.cpp`.
* `unittest/test_database_factory.cpp`.
* `integration/` (new): integration tests scripting a "mini-server" with dummy transports.

## 5. Non-regression guarantees

* No change to network protocol, save format, Lua API, or database format.
* `Server::Server` (current signature) stays compilable: the legacy constructor continues to exist (step 7).
* The `luantiserver` binary compiles and starts without configuration change.
* Existing tests stay green; `friend`s are removed/cleaned progressively.

## 6. Success criteria

1. **`Server.h` ≤ 250 lines**, `Server.cpp` ≤ 1500 lines.
2. **Zero `friend class Test*`** in `Server`.
3. **Zero direct access to `g_settings`/`g_profiler`** from `Server::*` (only via `ISettingsProvider`).
4. **≥ 80 % line coverage** on new services (reasonable target; measurable via `gcov`/`llvm-cov`).
5. **At least 10 new unit tests** on services and dispatcher.
6. **The `toServerCommandTable` array no longer contains pointers to `Server` members**.

## 7. Risks and mitigations

| Risk | Mitigation |
|---|---|
| Threading regression (lock order of `m_env_mutex`/`m_con` is subtle) | Step 2: create a multi-thread stress test replaying dispatch. Keep a `git bisect`/`tsan` pass at each step. |
| Dependency cycle between new services | Build an explicit dependency graph in `iservices.h` (comment), validate with a `Dependencies` construction test. |
| Disproportionate effort migrating ~25 handlers | "Strangler" approach: shim + dual routing; each migrated handler is committed atomically. |
| `con::IConnection` internal mutexes vs new `INetSender` | Keep the existing thread-safe implementation, just adapt the boundary. |
| CI cost / build time | Refactorings in small PRs; existing CI (`cmake --build` + unit tests) is enough. |

## 8. Estimates

* Steps 1-3 (dispatcher core + 1 service): ~3 weeks.
* Steps 4-6 (business services): ~5 weeks.
* Steps 7-9 (DI, cleanup, tests): ~3 weeks.
* **Total: ~11 weeks** for a complete refactor, alongside a release.

## 9. First concrete action (to validate)

Start with **step 1** (extracted `ShutdownController`) which is the least risky, the most visible, and that establishes the "standalone class + injected interface" pattern.

Decisions to make with the user:
- Keep `Server`'s legacy constructor (backward compat) or require DI (clean break)?
- `con::IConnection`: rename it to `ITransport` (cosmetic but clarifies intent) or keep it?
- Step 0: create `src/server/services/` (new subfolder) or stay flat in `src/server/`?

---

## 10. Detailed sub-plan: User session lifecycle, packet handlers and routing

This section drills into the part of the system that carries the most architectural risk: how a remote user goes from a raw TCP packet to a fully-initialized, in-game session, and how the various commands move through the system. The goal is to make this flow **pluggable, testable end-to-end without a real network**, while **strictly preserving** the current high-throughput, low-latency hot path (the server handles a *lot* of small `TOSERVER_PLAYERPOS` packets per second and bursts of `TOSERVER_GOTBLOCKS`).

### 10.0 Performance & threading constraints (game-critical, do not regress)

Luanti is a real-time game server. The receive/dispatch path is the **hottest path in the engine**; the send path feeds an already-async network thread. Any refactor must respect these facts:

1. **The receive thread is owned by `con::Connection` and runs independently** (`src/network/mtp/threads.{h,cpp}`: `ConnectionReceiveThread` produces packets into `m_incoming_queue`). `Server::Receive` only **drains** that queue; it does not block on the socket.
2. **The send thread is owned by `con::Connection` too** (`ConnectionSendThread` consumes `m_outgoing_queue`). `Server::Send*` enqueues into that queue; it does not call the socket directly. This is the key reason the current code can ship ~70 high-level `Send*` methods without becoming a bottleneck.
3. **`m_con` is `std::shared_ptr<con::IConnection>`** and is already thread-safe (mutex internally). We must keep that contract — **`INetSender` must not introduce a second mutex in front of `m_con->Send`**.
4. **Per-packet cost is small but budgeted**: target ≤ ~1–2 µs of overhead per packet on the receive hot path (drain loop). No allocation, no virtual call chain longer than 1, no extra `std::function` indirection **on the hot path** (function-pointer dispatch is fine; `std::function` is not, unless we use small-buffer optimization and measure).
5. **The envlock is taken once per packet, held for the whole handler chain** (current code, `src/server.cpp:1322`). This serializes all packet handling. We **must not** add another global lock per packet.
6. **Bulk block sending already uses a per-session priority queue** (`RemoteClient::GetNextBlocks` + `PrioritySortedBlockTransfer`). Keep it. Do not centralize block picking in a global queue.

Concretely this means:

* `INetSender` is **not** a smart object; in production it is a thin `static` helper namespace (or a struct with only the `con::IConnection&` ref) that calls `m_con->Send` directly. The interface exists **only** so tests can substitute `MockNetSender`. In release builds the v-table indirection is on cold paths (HP, breath, sky, hud…) and the dispatcher is a direct function pointer.
* `ServerDispatcher` uses a **`std::array<HandlerEntry, TOSERVER_NUM_MSG_TYPES>`** of function pointers (or a flat POD table, not `std::function`) for the actual hot dispatch. `std::function` is reserved for **test-only** handler registration.
* `Session` lookup in the hot path is a **single hash-table lookup** under the registry's recursive mutex; we keep `std::recursive_mutex` (same as current `ClientInterface`) so re-entry is free.
* **No allocation on the receive hot path** when the packet is malformed/dropped: the preCheck returns early without constructing a `NetworkPacket` reply.
* **No new locks on outgoing** path: `INetSender::send` is a wrapper around `m_con->Send(peer, channel, pkt, reliable)` and nothing else.

A benchmark (`benchmark/`) will be added to measure packets/sec on the dispatch path before and after each step (sanity check, not a gating CI step).

### 10.1 Current state (recap, code-anchored)

The relevant data and code paths today:

| Concern | Today | Location |
|---|---|---|
| TCP-level peer lifecycle | `con::IConnection` + `con::IPeer` (already an abstraction, good) | `src/network/connection.h`, `src/network/connection.cpp` (impl in `mtp/`) |
| Per-peer session state | `RemoteClient` + `ClientInterface` | `src/server/clientiface.h` (530 lines, two classes tightly coupled) |
| Per-client state machine | `ClientState` enum (10 states) + `CSE_*` events, embedded in `ClientInterface` | `src/clientiface.h:162-187` |
| Packet reception loop | `Server::Receive` reads `m_con->ReceiveTimeoutMs` and dispatches one by one | `src/server.cpp:1127-1182` |
| Per-packet envelope validation | `Server::ProcessData` takes envlock first, checks opcode validity, then state, then calls `handleCommand` | `src/server.cpp:1319-1371` |
| Opcode table | `toServerCommandTable[ToServerCommand]` of `ToServerCommandHandler` containing `void (Server::*)(NetworkPacket*)` | `src/network/serveropcodes.h:19-33`, populated in `serveropcodes.cpp` |
| Per-command handler | ~25 `Server::handleCommand_X(NetworkPacket*)` methods | `src/network/serverpackethandler.cpp:36+` (1839 lines) |
| Cross-cutting response packets | `Server::Send*` methods (HP, breath, time, hud, sky, sun, …) | `src/server.cpp` (lines 1465+ for `SendMovement`, 1485+ for HP, 1869+ for HUD, 1953+ for sky…) |
| Auth subsystem | `Server::handleCommand_FirstSrp/SrpBytesA/SrpBytesM`, `acceptAuth`, `DenyAccess` | `src/network/serverpackethandler.cpp` + `src/server.cpp:3059-3112` |
| Mod channels | `Server::joinModChannel/leaveModChannel/sendModChannelMessage` | `src/server.h:432-435` |
| Inventory actions | `ServerInventoryManager` (already separate, good) | `src/server/serverinventorymgr.cpp` |
| Map blocks | `Server::SendBlocks` and `RemoteClient::GetNextBlocks` (the latter is **already** a method of `RemoteClient` — useful) | `src/server.cpp:2573+`, `src/server/clientiface.h:246` |

Locking order currently in effect (subtle and worth preserving):
1. **`m_env_mutex` is taken first** in `Server::ProcessData` (`src/server.cpp:1322`).
2. Then `m_clients.m_clients_mutex` (recursive, taken in many `Server::*` methods via `ClientInterface::AutoLock`).
3. Then `m_con` (which has its own internal mutex).
4. The emerge thread also takes `m_env_mutex`, which is why `Server::yieldToOtherThreads` exists (`src/server.cpp:1184`).

### 10.2 Target: a clean three-layer pipeline for incoming packets

```
        ┌─────────────────────────────────────────────────────────────┐
  (1)   │  Transport layer (existing, untouched)                      │
        │  con::IConnection recv thread  ──► m_incoming_queue         │
        │  IncomingPacketPump (drain loop in ServerThread, hot path)   │
        │   - lockless drain: pop a packet                            │
        │   - 1 hashmap lookup: session id → Session&                 │
        │   - 1 array lookup: opcode → handler fn ptr                 │
        │   - call handler (envlock held for the duration)            │
        └─────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
        ┌─────────────────────────────────────────────────────────────┐
  (2)   │  Session layer (replaces ClientInterface for game state)    │
        │  SessionRegistry  +  Session  (one per peer)                │
        │   - owns state machine, name, addr, version, lang, SAO link │
        │   - holds Session& handed to handlers (ref, not id)         │
        │   - per-step enqueueOutgoing + flushAllOutgoing             │
        └─────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
        ┌─────────────────────────────────────────────────────────────┐
  (3)   │  Dispatch + Handler layer                                   │
        │  ServerDispatcher: opcode/state -> PacketHandler            │
        │  PacketHandler(ServerContext&, NetworkPacket&)              │
        │   - ServerContext bundles services, sender, env, scripting  │
        │   - handler is a function pointer (no std::function)         │
        └─────────────────────────────────────────────────────────────┘
```

Each layer is independently testable, and the wiring between them is **a single composition step in `Server::Server`**.

**Performance contract of the hot path** (single packet):

| Step | Cost target | Notes |
|---|---|---|
| Drain from `m_incoming_queue` | ~constant | existing code |
| `SessionRegistry::get(peer_id)` (hashmap lookup, recursive mutex) | ~1 µs | pre-`get` is a hot read; lock is already held by envlock holder or uncontended |
| `dispatcher.preCheck(opcode, session)` (state machine check) | ~50 ns | branch on `session.state()` and table lookup |
| `dispatcher.dispatch(opcode, ctx, pkt)` (fn pointer call) | ~5 ns | no v-table, no allocation |
| Handler execution | unchanged | same code, just different ABI (gets `Session&` instead of `session_t`) |
| `INetSender::send*` on the way out (when applicable) | ~0 (existing) | wraps `m_con->Send` |

No allocation, no extra mutex acquisition, no extra `std::function` call in this path.

### 10.3 The new `Session` object (per-peer state) — **first deliverable**

Today, the per-peer state is split awkwardly between:
- `con::IPeer` (transport layer: address, channels)
- `RemoteClient` (game-level: serialization version, name, blocks sent, m_state, m_media_sent, m_known_objects, …)
- `PlayerSAO` (game-world: position, hp, inventory, hud elements, known-by-count)
- Various `Server` members keyed by `session_t` (formspec state data, sound play handles per peer, particle buffers, etc.)

We extract a **`Session` class** that owns the **game-level** per-peer state, with `RemoteClient` becoming a thin alias for backward compat:

```cpp
// src/server/session.h
class Session {
public:
    Session(session_t id, Address addr, ClientState initial = CS_Created);
    ~Session();

    // Identity
    session_t id() const { return m_id; }
    const Address &address() const { return m_addr; }

    // State machine (now internal, not on ClientInterface)
    ClientState state() const { return m_state; }
    void notifyEvent(ClientStateEvent evt);   // asserts legal transitions, throws on illegal

    // Link to game-world counterpart
    void attachPlayer(PlayerSAO *sao);
    void detachPlayer();
    PlayerSAO *player() const { return m_player; }

    // Outgoing packet buffer (per session)
    // - Filled by services during step()
    // - Flushed by SessionRegistry::flushAllOutgoing()
    // - Hot handlers (PlayerPos, GotBlocks) call INetSender::send directly,
    //   bypassing the outbox, to keep latency low. The outbox is for
    //   per-step batched sends (e.g. block sends at end of step).
    void enqueueOutgoing(std::unique_ptr<NetworkPacket> pkt, u8 channel, bool reliable);
    void flushOutgoing(INetSender &sender);

    // Per-session caches (moved verbatim from RemoteClient)
    SerializedBlockCache    block_cache;
    std::unordered_set<v3s16> blocks_sent, blocks_sending, blocks_occ;
    std::unordered_set<std::string> media_sent;
    std::set<u16>           known_objects;
    std::string             formspec_state;
    std::string             lang_code;
    u8                      serialization_version = SER_FMT_VER_INVALID;
    u8                      pending_serialization_version = SER_FMT_VER_INVALID;
    u16                     net_proto_version = 0;
    AuthMechanism           chosen_mech = AUTH_MECHANISM_NONE;
    u32                     allowed_auth_mechs = 0;
    void                   *auth_data = nullptr;
    std::string             enc_pwd;
    bool                    create_player_on_auth_success = false;
    float                   time_from_building = 9999.f;

private:
    const session_t         m_id;
    Address                 m_addr;
    ClientState             m_state = CS_Created;
    PlayerSAO              *m_player = nullptr;
    std::deque<OutgoingItem> m_outbox;   // protected by SessionRegistry's lock
};
```

`Session` is **not** thread-safe on its own; the `SessionRegistry` (see below) is the single owner of the session map and its lock.

The state machine diagram (currently in a comment in `clientiface.h:28-153`) is encoded directly in `Session::notifyEvent` with `assert`/exception for illegal transitions. **This is the single biggest win**: the state machine becomes executable, type-checked, and unit-testable independently.

### 10.4 The new `SessionRegistry` (replaces `ClientInterface` for game-level concerns)

```cpp
// src/server/session_registry.h
class SessionRegistry {
public:
    SessionRegistry(std::shared_ptr<con::IConnection> con);
    ~SessionRegistry();

    // Transport -> Session
    Session &onPeerAdded(session_t id, const Address &addr);
    void     onPeerRemoved(session_t id, bool timeout);

    // Lookup (under registry lock)
    Session *get(session_t id);                              // returns nullptr if absent
    Session *getLocked(session_t id, ClientState min_state = CS_Active);

    // Iteration
    std::vector<Session *> active();
    std::vector<std::string> playerNames() const;

    // Per-step
    void step(float dtime);
    void flushAllOutgoing(INetSender &sender);               // called from Server::AsyncRunStep

    // Broadcasts
    void broadcast(const NetworkPacket &pkt, ClientState min_state = CS_Active);

    // Connection thunks (preserves locking order)
    void send(session_t id, const NetworkPacket &pkt);
    void sendCustom(session_t id, u8 channel, const NetworkPacket &pkt, bool reliable);
    Address addressOf(session_t id);

    // Auth-specific (used by AuthService)
    void setAuthData(session_t id, AuthMechanism mech, void *data);
    void *getAuthData(session_t id);

private:
    std::shared_ptr<con::IConnection> m_con;
    mutable std::recursive_mutex      m_mutex;     // same as current ClientInterface
    std::unordered_map<session_t, std::unique_ptr<Session>> m_sessions;
    std::vector<std::string>          m_player_names;
};
```

`ClientInterface` is **kept as a thin alias** (`using ClientInterface = SessionRegistry;`) for one release, then removed.

### 10.5 The new `INetSender` (transport-side abstraction for handlers)

Currently, every handler that wants to send a packet reaches for `Server::Send` or one of the ~50 `Server::SendXxx` helpers that internally call `m_clients.send` / `m_con->Send`. The result: handlers cannot be tested without a real connection, and the surface area of `Server` is enormous.

```cpp
// src/network/net_sender.h
class INetSender {
public:
    virtual ~INetSender() = default;

    // Low-level — must be cheap, must forward to the async send queue.
    virtual void send(session_t peer_id, const NetworkPacket &pkt) = 0;
    virtual void sendAll(const NetworkPacket &pkt, ClientState min = CS_Active) = 0;

    // Per-session high-level helpers (formerly Server::Send*).
    // Implemented in the .cpp in terms of `send` + packet construction.
    // They are out of the hot path; the hot path handlers (PlayerPos, GotBlocks,
    // InventoryAction) only use the low-level `send` directly.
    void sendAccessDenied(session_t, AccessDeniedCode, std::string_view = "", bool reconnect = false);
    void sendChatMessage(session_t, const ChatMessage &);
    void sendTimeOfDay(session_t, u16 time, f32 speed);
    void sendPlayerHP(session_t, u16 hp, bool effect);
    void sendPlayerBreath(session_t, u16 breath);
    void sendMovePlayer(session_t, const v3f &pos, f32 pitch, f32 yaw);
    void sendPlayerSpeed(session_t, const v3f &vel);
    void sendPlayerFov(session_t, f32 fov);
    void sendCamera(session_t, const v3f &pos, const v3f &dir);
    void sendInventory(session_t, const Inventory &, bool incremental);
    void sendDetachedInventory(session_t, const std::string &name, const Inventory &);
    void sendShowFormspec(session_t, const std::string &formspec, const std::string &formname);
    void sendPlayerPrivileges(session_t, const std::set<std::string> &privs);
    void sendHUDAdd(session_t, u32 id, const HudElement &);
    void sendHUDRemove(session_t, u32 id);
    void sendHUDChange(session_t, u32 id, HudElementStat stat, const void *value);
    void sendHUDSetFlags(session_t, u32 flags, u32 mask);
    void sendSetSky(session_t, const SkyboxParams &);
    void sendSetSun(session_t, const SunParams &);
    void sendSetMoon(session_t, const MoonParams &);
    void sendSetStars(session_t, const StarParams &);
    void sendCloudParams(session_t, const CloudParams &);
    void sendOverrideDayNightRatio(session_t, bool do_override, f32 ratio);
    void sendSetLighting(session_t, const Lighting &);
    void sendMinimapModes(session_t, const std::vector<MinimapMode> &, size_t wanted);
    void sendSpawnParticle(session_t, const ParticleParameters &);
    void sendAddParticleSpawner(session_t, u32 id, const ParticleSpawnerParameters &);
    void sendDeleteParticleSpawner(session_t, u32 id);
    void sendBlock(session_t, const v3s16 &pos, std::string_view data, u8 ver);
    void sendMediaAnnouncement(session_t, const std::vector<MediaInfo> &);
    void sendMedia(session_t, const std::string &filename, std::string_view data);
    void sendCSMRestrictionFlags(session_t, u64 flags);
    void sendItemDef(session_t, const IItemDefManager &, u16 proto);
    void sendNodeDef(session_t, const NodeDefManager &, u16 proto);
    void sendActiveObjectRemoveAdd(session_t, const std::vector<u16> &add, const std::vector<u16> &remove);
    void sendActiveObjectMessages(session_t, const std::string &datas, bool reliable);
    void sendLocalPlayerAnimations(session_t, v2f frames[4], f32 speed);
    void sendEyeOffset(session_t, v3f first, v3f third, v3f third_front);
    void sendFormspecPrepend(session_t, const std::string &);
    void sendInventoryFormspec(session_t, const std::string &);
    // ... ~70 methods in total
};
```

Two implementations:

* **`ConnectionNetSender`** — final class, owns a `std::shared_ptr<con::IConnection>` and a `SessionRegistry&`. Translates high-level `sendXxx` into a `NetworkPacket` + `m_con->Send`. The `send` method is **`final`, non-virtual from outside, and inlinable**:
  ```cpp
  void ConnectionNetSender::send(session_t id, const NetworkPacket &pkt) final {
      m_con->Send(id, pkt.getChannel(), const_cast<NetworkPacket*>(&pkt), pkt.isReliable());
  }
  ```
  This compiles to the same code as today's `Server::Send`.
* **`MockNetSender`** — records every sent packet in a `std::vector<SentRecord>` where `SentRecord { session_t peer; u16 opcode; std::string payload; u8 channel; bool reliable; }`. Lets tests assert: *"when INIT arrives with name='bob', the server sent TOCLIENT_HELLO, then TOCLIENT_AUTH_ACCEPT after SRP…"*.

The high-level methods are **defaulted** in the base class (packet construction + call to `send`) so `MockNetSender` only needs to override the low-level `send` to capture.

### 10.6 The new `ServerDispatcher` (replaces the `toServerCommandTable` indirection)

```cpp
// src/network/server_dispatcher.h
struct ServerContext {
    IServerServices &services;
    INetSender       &sender;
    Session          &session;
    ServerEnvironment &env;
    ServerScripting  &script;
    MetricsBackend   &metrics;
    // Helpers (inlinable)
    std::string_view getName() const { return session.name(); }
    bool checkPriv(const std::string &p) const;
    PlayerSAO *getPlayerSAO() const { return session.player(); }
    // ...
};

using PacketHandlerFn = void (*)(ServerContext &, NetworkPacket &);

struct HandlerEntry {
    ToServerConnectionState state;
    PacketHandlerFn         fn;       // raw function pointer, never std::function
    const char             *name;
};

class ServerDispatcher {
public:
    ServerDispatcher();

    // Build a dispatcher that knows the current Luanti opcodes.
    static ServerDispatcher withBuiltinHandlers();

    // For tests, register only what you need.
    void registerHandler(u16 opcode, HandlerEntry entry);

    // Main entry point — replaces Server::ProcessData dispatch.
    // Returns true if a handler was invoked.
    FORCE_INLINE bool dispatch(u16 opcode, ServerContext &ctx, NetworkPacket &pkt) const {
        const HandlerEntry &e = m_table[opcode];
        if (LIKELY(e.fn)) {
            e.fn(ctx, pkt);
            return true;
        }
        return false;
    }

    // Pre/post checks (state, envlock, etc.) — factored out from ProcessData.
    enum class PreCheckResult : u8 { Ok, UnknownOpcode, BadState, BadSerFmt, Drop };
    PreCheckResult preCheck(u16 opcode, const Session &session) const;

    // Lookup (for logging, exceptions)
    const HandlerEntry &get(u16 opcode) const { return m_table[opcode]; }
    const char *opcodeName(u16 opcode) const { return m_table[opcode].name; }

private:
    // Dense array indexed by opcode; size known at compile time; no allocation.
    // For test dispatchers that want sparse, use the variant with std::array<optional<HandlerEntry>>.
    std::array<HandlerEntry, TOSERVER_NUM_MSG_TYPES> m_table;
};
```

Why a function pointer table (and not `std::function`):
* `TOSERVER_PLAYERPOS` is the most frequent packet in the game (sent at 20 Hz by every client). Each call goes through the dispatch. A function-pointer call is one indirect call; a `std::function` call is one indirect call + a `bool` check for empty + (in the general case) a heap-allocated closure pointer dereference. We refuse to pay that.
* Tests that want a custom handler can use a parallel `ServerDispatcherForTest` whose table is `std::array<std::optional<HandlerEntry>, N>`. Production code never instantiates it.

Concrete signature for a migrated handler:

```cpp
// in serverpackethandler.cpp
static void handlePlayerPos(ServerContext &ctx, NetworkPacket &pkt) {
    auto &session = ctx.session;
    if (!session.player()) return;
    ctx.services.processPlayerPos(session, *session.player(), pkt);
}

// Registered once in withBuiltinHandlers():
m_table[TOSERVER_PLAYERPOS] = {
    .state = TOSERVER_STATE_INGAME,
    .fn    = &handlePlayerPos,
    .name  = "TOSERVER_PLAYERPOS",
};
```

**Note the changes vs. today**:
* The handler gets a **`Session&`**, not a `session_t` and ad-hoc lookups in `m_clients`.
* The handler gets **`INetSender&`**, not a `Server*`.
* All cross-cutting state (privileges, name, SAO) is reachable through `ctx.session`.
* The function is **`static`**, so the dispatcher holds a plain pointer — no `this`, no allocation.

### 10.7 How `Server::ProcessData` becomes thin

```cpp
void Server::processIncoming(NetworkPacket &pkt, SessionRegistry &sessions) {
    auto *session = sessions.get(pkt.getPeerId());
    if (!session) {
        // Peer arrived but not yet registered — the transport layer
        // should have created one. Drop.
        return;
    }

    // Lock the env (per current contract: envlock first).
    EnvAutoLock envlock(this);

    const u16 opcode = pkt.getCommand();
    switch (m_dispatcher.preCheck(opcode, *session)) {
        case ServerDispatcher::PreCheckResult::Ok: break;
        case ServerDispatcher::PreCheckResult::UnknownOpcode:
            infostream << "Server: Ignoring unknown command " << opcode << std::endl;
            return;
        case ServerDispatcher::PreCheckResult::BadState: {
            const char *name = m_dispatcher.opcodeName(opcode);
            verbosestream << "Server: ignoring " << name << " from peer "
                          << session->id() << " in state "
                          << ClientInterface::state2Name(session->state()) << std::endl;
            return;
        }
        case ServerDispatcher::PreCheckResult::BadSerFmt:
            errorstream << "Server: Peer serialization format invalid. Skipping "
                        << m_dispatcher.opcodeName(opcode) << std::endl;
            return;
        case ServerDispatcher::PreCheckResult::Drop: return;
    }

    ServerContext ctx{
        .services = m_services,
        .sender   = *m_net_sender,
        .session  = *session,
        .env      = *m_env,
        .script   = *m_script,
        .metrics  = *m_metrics_backend,
    };
    m_dispatcher.dispatch(opcode, ctx, pkt);
}
```

`Server::Receive` becomes (semantically identical to today, only renamed):

```cpp
void Server::Receive(float min_time) {
    NetworkPacket pkt;
    auto remaining = /* … */;
    for (;;) {
        pkt.clear();
        if (!m_con->ReceiveTimeoutMs(&pkt, std::ceil(remaining() / 1000))) {
            if (remaining() > 0) continue;
            break;
        }
        m_packet_recv_counter->increment();
        try {
            m_session_registry->onPacket(pkt);   // updates session.serialization_version, state, etc.
            processIncoming(pkt, *m_session_registry);
        } catch (const SendFailedException &e) { /* same as today */ }
        catch (const con::InvalidIncomingDataException &) { /* … */ }
        // … all other catches preserved verbatim …
        m_packet_recv_processed_counter->increment();
    }
}
```

### 10.8 Initial session bootstrap: who creates the `Session`?

Two events trigger session lifecycle:

1. **`con::PeerHandler::peerAdded(IPeer*)`** — called by the transport when a TCP connection is accepted (`src/server.cpp:1387`).
2. **`con::PeerHandler::deletingPeer(IPeer*, bool timeout)`** — called on disconnect.

In the new design:

```cpp
void Server::peerAdded(con::IPeer *peer) {
    m_session_registry->onPeerAdded(peer->id, peer->getAddress());
}
void Server::deletingPeer(con::IPeer *peer, bool timeout) {
    m_session_registry->onPeerRemoved(peer->id, timeout);
}
```

These two are the **only** methods on `Server` that the transport calls; everything else is data-driven via the dispatcher.

For tests, **`MockTransport`** (a fake `con::IConnection`) plus a direct call to `m_session_registry->onPeerAdded(42, addr)` is enough — no real socket, no real encryption.

### 10.9 Per-service interaction with sessions

The proposed services consume `Session&` rather than `session_t`:

| Service | Today (where it gets a `session_t`) | After |
|---|---|---|
| `MediaService` | `Server::sendMediaAnnouncement(session_t, …)` | `mediaSvc.sendAnnouncement(Session&, …)` |
| `PlayerService` | `Server::hudAdd(RemotePlayer*, HudElement*)` (already takes `RemotePlayer*`, good) | unchanged signature, but called from handlers receiving `ctx.session.player()` |
| `IAuthorizationService` | `Server::handleCommand_FirstSrp`, `acceptAuth`, `denyIfBanned`, `checkPriv`, `getPlayerEffectivePrivs`, `setIpBanned/unsetIpBanned` | `authz.onFirstSrp(ctx, pkt)`, `authz.onSrpBytesA(ctx, pkt)`, `authz.checkConnection(ctx) -> AuthzDecision`, `authz.checkPriv(name, priv) -> bool`, `authz.ban/unban(...)` (see §11) |
| `WorldService` | `Server::AsyncRunStep` | `worldSvc.runPeriodic(dtime)`; reads `m_session_registry->active()` |
| `NotificationService` | `Server::notifyPlayer(name, msg)` | unchanged API; impl uses `m_session_registry` |

### 10.10 Locking strategy (preserved, encapsulated, never relaxed)

The single most error-prone thing in the current code is the lock order between `m_env_mutex`, `m_clients.m_clients_mutex`, and the `m_con` mutex. We **do not** change the order — we encapsulate it. **We do not add any new lock to the hot path.**

| Layer | Owns | Lock taken | Released | Hot path? |
|---|---|---|---|---|
| `con::Connection` recv thread | `m_incoming_queue` | per push | per push | yes (untouched) |
| `Server::Receive` drain | none | none | none | yes |
| `Server::processIncoming` | `EnvAutoLock` (env) | at entry | at exit | yes |
| `SessionRegistry` lookup | `m_mutex` (recursive, same as `ClientInterface`) | on `get`/`getLocked`/`broadcast`/`flushAllOutgoing` | on return | yes (held) |
| `INetSender::send` (production) | none — calls `m_con->Send` | n/a | n/a | yes |
| `m_con->Send` | internal `m_outgoing_queue` | per push | per push | yes (untouched) |
| `Server::AsyncRunStep` | `EnvAutoLock` for `m_env->step` | per step | per step | yes |
| `Server::AsyncRunStep` → `SendBlocks` | own `EnvAutoLock` + `ClientInterface::AutoLock` | nested | nested | yes |
| `Server::AsyncRunStep` → `flushAllOutgoing` | `ClientInterface::AutoLock` only | per step | per step | yes (bulk only) |

**Invariant** (must be preserved and asserted in debug builds): `env → sessions → con`. The dispatcher and handlers **must not** acquire `env`; if a handler needs an env operation, it goes through `ctx.services`, which provides the locking.

To make this enforceable, the `INetSender` and `SessionRegistry` interfaces expose only **const or post-lock** views (e.g. `Session::state()` reads the field directly because the caller is assumed to hold the registry lock; a non-locking `SessionRegistry::peek(id)` returns `nullptr` if the entry is currently locked for mutation — but in practice we never need that because the registry's mutex is recursive).

**Outbox model (clarification)**: hot handlers (PlayerPos, GotBlocks, InventoryAction, Interact, Damage, ChatMessage, RemovedSounds, NodeMetaFields, InventoryFields, HaveMedia) call `ctx.sender.send(...)` synchronously, exactly as today, with the exact same cost. Bulk operations (block sends at end of step, particle spawning batched per step, media sent after announcement ack) can use `Session::enqueueOutgoing` and be flushed at end of step. This preserves the **immediate** latency of small interactive packets and only batches the heavy ones — same pattern as today.

### 10.11 Migration order for handlers (strangler pattern, Session first)

To de-risk the migration of the 25 handlers, we use a **strangler table**: for a release window, both tables exist. The `Server` shim keeps the old `toServerCommandTable` populated with `Server::*` methods, but those methods become one-liners that delegate to `m_dispatcher.dispatchX(ctx, pkt)`. This way each handler can be converted independently and reverted if a regression appears.

**The user is right: `Session` should be first.** Reordered PRs:

| PR | What | Risk | Hot path impact |
|---|---|---|---|
| **#1 (NEW first)** | Extract `Session` + `SessionRegistry`. `RemoteClient` becomes a type alias of `Session`'s POD-per-peer block. `ClientInterface` becomes a type alias of `SessionRegistry`. No behavior change. Compile + run full test suite + run `benchmark/`. | Low — pure refactor, no behavior change. | None (same fields accessed in the same order) |
| #2 | Extract `INetSender` + `ConnectionNetSender`. `Server::Send*` become one-liners forwarding to `m_net_sender`. | Low — still same wire format. | None (`final` inline `send`) |
| #3 | Introduce `ServerDispatcher` (function-pointer table) but **not wired**; `withBuiltinHandlers()` is built and tested in isolation. | None. | n/a |
| #4 | Wire one hot path (`handleCommand_PlayerPos` + `handleCommand_GotBlocks` + `handleCommand_DeletedBlocks` + `handleCommand_InventoryAction` + `handleCommand_Interact`) end-to-end, with benchmark comparison. | Medium — touches the most-frequent packets. | **Measured vs. baseline** |
| #5 | Wire the auth/login path (`Init` + `Init2` + `FirstSrp` + `SrpBytesA` + `SrpBytesM` + `ClientReady`). | Medium — touches login flow. | Cold path |
| #6-N | One PR per ~3 handlers (group by area: media, blocks, inventory, mod channels, hud, sky/sun, particles, misc). | Medium each. | Mixed |
| Final | Remove the legacy `toServerCommandTable`, drop the `server.h` include in `serveropcodes.h`, remove `friend class Test*`. | Low. | n/a |

Each PR must:
1. Pass the existing `benchmark/` (within ±2 % of baseline on `dispatch_pkts_per_sec`).
2. Pass `test_moveaction.cpp`, `test_server_shutdown_state.cpp`, and the new tests added in that PR.
3. Be replayed through `tsan` and `asan` to catch any new race/leak.

### 10.12 New tests enabled by this sub-plan

1. **`test_session_state_machine.cpp`** — every legal/illegal transition of `ClientState` + `CSE_*`. Zero allocation, microsecond-fast.
2. **`test_session_registry.cpp`** — create/remove/find/getLocked, broadcast, send ordering. Includes a thread-sanitizer variant that hammers the registry from 4 threads.
3. **`test_net_sender_mock.cpp`** — `MockNetSender` records `SentRecord`s; assert that `sendAccessDenied` produces the right `NetworkPacket` payload (version-agnostic comparison).
4. **`test_server_dispatcher.cpp`** — for each registered opcode, build a synthetic `NetworkPacket`, call `dispatcher.dispatch`, assert the right downstream service was called (via mock service). Also tests `preCheck` for every (opcode, state) combination.
5. **`test_end_to_end_login.cpp`** (integration) — drives the four state transitions (Created → HelloSent → AwaitingInit2 → InitDone → DefinitionsSent → Active) using only `MockTransport` + `MockNetSender` + a fake `AuthDatabase`. Asserts the sequence of outgoing packets.
6. **`test_moveaction.cpp`** (existing) — now no longer needs `friend Server`; can call `worldSvc.processPlayerPos(Session&, …)` directly.
7. **`test_server_shutdown_state.cpp`** — covered by step 1, no longer needs friend.
8. **`test_dispatch_perf.cpp`** (microbenchmark, in `benchmark/`) — synthetic `PlayerPos` packet stream, measure pkts/sec, assert ≥ baseline × 0.98.

### 10.13 Open questions to validate with the user

*See §11 for the merged `IAuthorizationService` discussion.*

---

## 11. Consolidating Auth + Ban + Privs into `IAuthorizationService`

### 11.1 Rationale

The current code splits the "who is allowed to do what?" question across three different places on `Server`, and they're more entangled than they look:

| Concern | Today | Why it's actually one thing |
|---|---|---|
| **IP/name ban list** | `Server::BanManager` (raw ptr) + `setIpBanned`, `unsetIpBanned`, `getBanDescription`, `denyIfBanned` (`src/server.cpp:3454-3497`) | A ban is a **persistent negative authorization** attached to an identity. It must be consulted *before* SRP starts, and *during* SRP, and *after* SRP for privilege decisions. |
| **Authentication (SRP)** | `Server::handleCommand_FirstSrp/SrpBytesA/SrpBytesM` + `acceptAuth` + `DenyAccess` (`src/network/serverpackethandler.cpp` + `src/server.cpp:3059-3112`) | SRP state (chosen mech, `enc_pwd`, `auth_data`) currently lives on `RemoteClient`/`Session`. It is consumed by the same identity ("the player behind this peer") that bans and privs also describe. |
| **Privilege lookup** | `Server::getPlayerEffectivePrivs` + `checkPriv` + `reportPrivsModified` (`src/server.cpp:3405-3436`) | Privs are the **granular positive authorization** for in-game actions. They depend on the auth database (the `privileges` field of `AuthEntry`, `src/database/database.h:57-63`) and can be granted/revoked at runtime. |

All three read/write the same `IAuthDatabase`, all three key off the same identity (playername, or peer IP before identity is known), and all three return yes/no decisions that the network layer translates into a packet. Splitting them across three services means:
* `Server` keeps three sets of public methods that all "ask the same question" (`isAllowed(peer/name, action)`) with subtly different parameters;
* tests have to mock three services to test "can this user kick that other user?";
* hot-path handlers (every command, in practice) may need to consult *two* of them in sequence, doubling the lookup overhead.

### 11.2 Target interface

```cpp
// src/server/services/authorization_service.h
class IAuthorizationService {
public:
    virtual ~IAuthorizationService() = default;

    // ---- Identity & ban list (pre-auth) -------------------------------
    enum class ConnectionVerdict {
        Allow,
        DenyBanned,
        DenyUserLimit,
        DenyUnexpected,
        DeferAuthRequired,
    };
    struct ConnectionContext {
        const Address &peer_addr;
        const std::string &claimed_name;
        bool             is_singleplayer;
    };
    virtual ConnectionVerdict checkConnection(const ConnectionContext &) = 0;
    virtual void banByIp(const std::string &ip, const std::string &name) = 0;
    virtual void unbanByIpOrName(const std::string &ip_or_name) = 0;
    virtual std::string describeBan(const std::string &ip_or_name) = 0;

    // ---- Authentication handshake (state lives on Session) ------------
    // All auth state (chosen_mech, enc_pwd, srp_data) is stored on the Session
    // object, not in the service. The service is stateless w.r.t. connections.
    virtual void onFirstSrp(ServerContext &ctx, NetworkPacket &pkt) = 0;
    virtual void onSrpBytesA(ServerContext &ctx, NetworkPacket &pkt) = 0;
    virtual void onSrpBytesM(ServerContext &ctx, NetworkPacket &pkt) = 0;
    virtual void acceptAuth(ServerContext &ctx, bool for_sudo) = 0;
    virtual void denyAuth(ServerContext &ctx, AccessDeniedCode code,
                          std::string_view custom = "", bool reconnect = false) = 0;
    virtual void denySudo(ServerContext &ctx) = 0;

    // ---- Privilege lookup (post-auth) ---------------------------------
    virtual std::set<std::string>
        getEffectivePrivs(const std::string &player_name) = 0;
    virtual bool checkPriv(const std::string &player_name,
                           const std::string &priv) = 0;

    // Notify clients that a player's priv set changed.
    virtual void reportPrivsModified(const std::string &name = "") = 0;
};
```

### 11.3 Why this is one service, not three

1. **Shared read of `IAuthDatabase`.** `getEffectivePrivs` and SRP both need the `AuthEntry` for the playername. Caching the `AuthEntry` once on the `Session` (after SRP succeeds) makes privilege lookups a pure read off the `Session` for the lifetime of the connection. No second database hit.
2. **Ordering of checks is fixed and known**: (a) ban list → (b) user limit → (c) SRP handshake → (d) privilege lookup. Keeping the ordering in a single service (a `checkConnection` verdict + an `onFirstSrp/onSrpBytesA/onSrpBytesM/acceptAuth` state machine) prevents handlers from doing them in the wrong order.
3. **Auth state belongs to the Session, not the service.** The state machine (`AWAITING_SRP_BYTES_A` → `AWAITING_SRP_BYTES_M` → `AUTHENTICATED` → `IN_SUDO_MODE`) is added to `Session` as new sub-states inside `ClientState::CS_AwaitingInit2`/etc. The service reads/writes this state through `ServerContext::session`. The service itself is **stateless** — easily mockable.
4. **Tests are dramatically simpler.** A single `MockAuthorizationService` (returning whatever `checkConnection`/`checkPriv`/etc. verdict the test wants) replaces three separate mocks.
5. **Hot-path simplification.** Handlers that need to gate an action (e.g. `TOSERVER_INTERACT` checks anti-cheat + privs) call **one method**: `if (!ctx.authz.checkPriv(name, "interact")) deny;` — instead of two lookups.

### 11.4 Implementation sketch

```cpp
class AuthorizationService : public IAuthorizationService {
public:
    AuthorizationService(std::unique_ptr<IAuthDatabase> auth_db,
                         std::unique_ptr<BanManager> bans,
                         ISettingsProvider &settings);

    // The SRP handlers are pure moves of the existing bodies from
    // serverpackethandler.cpp. Auth state (mec, srp_data) lives on
    // ctx.session, not in this class.
    void onFirstSrp(ServerContext &ctx, NetworkPacket &pkt) override;
    void onSrpBytesA(ServerContext &ctx, NetworkPacket &pkt) override;
    void onSrpBytesM(ServerContext &ctx, NetworkPacket &pkt) override;

    // Lookup path: if the session has a cached AuthEntry, use it; otherwise
    // hit the DB and cache the result on the session. (Same effect as today,
    // but the cache is explicit and testable.)
    std::set<std::string> getEffectivePrivs(const std::string &name) override;

private:
    std::unique_ptr<IAuthDatabase> m_auth_db;
    std::unique_ptr<BanManager>    m_bans;
    ISettingsProvider             &m_settings;
};
```

### 11.5 Migration impact

| Existing code | After |
|---|---|
| `Server::handleCommand_FirstSrp` (in `serverpackethandler.cpp`) | `AuthorizationService::onFirstSrp` registered in `ServerDispatcher::withBuiltinHandlers()` |
| `Server::handleCommand_SrpBytesA` | `AuthorizationService::onSrpBytesA` |
| `Server::handleCommand_SrpBytesM` | `AuthorizationService::onSrpBytesM` |
| `Server::acceptAuth` | `AuthorizationService::acceptAuth` (the `RemoteClient::setEncryptedPassword` etc. moves to `Session`) |
| `Server::DenyAccess` / `Server::DenySudoAccess` | `AuthorizationService::denyAuth` / `denySudo` |
| `Server::getPlayerEffectivePrivs` / `Server::checkPriv` | `IAuthorizationService::getEffectivePrivs` / `checkPriv` (same callers, `ctx.authz.…` instead of `services.…`) |
| `Server::setIpBanned` / `Server::unsetIpBanned` / `Server::getBanDescription` | `IAuthorizationService::banByIp` / `unbanByIpOrName` / `describeBan` (callers unchanged in modding API) |
| `Server::denyIfBanned` | Folded into `IAuthorizationService::checkConnection` |

### 11.6 Hot-path / threading notes

* `checkPriv` and `getEffectivePrivs` are called from handlers **under envlock** (same as today). They do a `set` lookup — O(priv_count), small constant in practice. No allocation on the hot path; the result is a `const std::set<std::string> &` borrowed from a per-session cache.
* `checkConnection` is called once per new peer, **before** envlock — it's a single hashmap lookup in the in-memory ban list, plus a counter check.
* The SRP handlers (called once per peer on login) are **cold path**; the existing code is not on the hot path so we can use `std::function`-friendly patterns if needed (we won't, we'll use fn pointers for consistency).
* No new locks introduced. The auth DB is thread-safe (already designed for concurrent reads; writes go through `m_env_mutex` for the duration of the auth flow). The ban list is currently protected by `m_env_mutex`; we keep that, since `Server::setIpBanned` is called from Lua (mod channel) and must serialize with the auth check.

### 11.7 Tests enabled

* `test_authorization_service.cpp` — with `InMemoryAuthDatabase` + `InMemoryBanList`:
  * `checkConnection` returns `DenyBanned` for a banned IP, `Allow` otherwise.
  * `checkConnection` returns `DenyUserLimit` when the limit is reached.
  * SRP happy path: `onFirstSrp` → `onSrpBytesA` → `onSrpBytesM` → `acceptAuth` produces the right sequence of outgoing packets via `MockNetSender`.
  * SRP failure: a wrong `M` causes `denyAuth(SERVER_ACCESSDENIED_WRONG_PASSWORD)`.
  * `getEffectivePrivs` honors `AuthEntry::privileges` plus the `default_privs` setting.
  * `reportPrivsModified` with `name=""` broadcasts `TOCLIENT_PRIVILEGES_UPDATE` to all clients.
* The existing `test_ban.cpp` and `test_srp_auth.cpp` continue to work (they test the DB and SRP primitives, which are unchanged).
* `test_moveaction.cpp` — can now stub the `MockAuthorizationService::checkPriv` to deny the move and assert the player is denied.

### 11.8 Open question on this section

* Should the per-session `AuthEntry` cache live on `Session` (recommended) or stay inside the `AuthorizationService` keyed by `session_t`? Living on `Session` is more cohesive (everything about a peer is in one place) and survives service restarts cleanly. Confirm.

### 10.13 Open questions to validate with the user

1. **Session ↔ RemotePlayer**: should `Session` *own* a `RemotePlayer*` (or `PlayerSAO*`), or stay orthogonal and let `PlayerService` keep a `session_t → PlayerSAO*` map? Owning is simpler but creates a circular reference (`PlayerSAO` knows its `session_t`). **Recommendation: `Session` owns a `PlayerSAO*` weak-ish pointer (`raw` guarded by the registry's lock — same as today's `m_clients` map).**
2. **Outbox model**: hot handlers continue to call `INetSender::send` synchronously (zero overhead vs. today). Bulk sends (blocks, particles) use the per-session outbox, flushed at end of step. **Confirm this is the desired split.**
3. **Mod channels and Session**: `ModChannelMgr` is currently server-global. Should `Session` carry its joined-channels set, or stay global? **Recommendation: global, since channels are pubsub-style across the server.**
4. **Packet ordering for in-flight blocks**: `RemoteClient` already tracks `m_blocks_sending`. Keep on `Session`, fine. No question, just confirming.
5. **Backwards compatibility window**: keep the legacy `toServerCommandTable` and `handleCommand_*` shim for 1 release, or remove in the same PR as step 3? **Recommendation: keep for 1 release (safer).**
6. **Benchmark gating**: should `test_dispatch_perf` be a CI gate (fail if perf regresses > 2 %), or a soft warning? **Recommendation: soft warning in CI, hard gate before each release.** Confirm.
7. **Authorization consolidation** (see §11): confirm you want the merged `IAuthorizationService` (auth + ban + privs in one) rather than three separate services. The merged service is stateless (state on `Session`), so it's still testable in isolation.
8. **Per-session `AuthEntry` cache**: should the `AuthEntry` fetched at `acceptAuth` time be cached on `Session` (recommended — no DB hit on every priv check), or re-read each time? Confirm.

---

## 12. TODO list — Extract `INetSender` and `ConnectionNetSender`

Scope: deliver the PR #2 of §10.11 in isolation. The end state is a new `INetSender` interface with two implementations (`ConnectionNetSender` for production, `MockNetSender` for tests), and `Server` keeping thin shims that delegate to it. **No behavior change, no wire-format change, no measurable perf regression on the hot path.**

### Phase A — Inventory & scaffold (≈ half a day)

- [ ] **A1.** Run `rg -n '^\s*void Server::Send' src/server.cpp` to enumerate the 47 `Server::Send*` methods. Save the list to `doc/refactor/netsender_methods.txt` for review.
- [ ] **A2.** Create the new header `src/network/net_sender.h` with the `INetSender` interface as drafted in §10.5 (low-level `send` + `sendAll` pure virtual, high-level `sendXxx` defaulted). Use a forward declaration of `NetworkPacket` and pass by `const &` in defaulted methods.
- [ ] **A3.** Create the empty implementation file `src/network/net_sender.cpp` (the defaulted methods will be filled in phase C).
- [ ] **A4.** Add the two files to `src/network/CMakeLists.txt` next to the existing `clientpackethandler.cpp` entry.
- [ ] **A5.** Verify the project still builds (`cmake --build build`) with the empty scaffold.

### Phase B — Low-level `ConnectionNetSender` (≈ 1 day, no behavior change)

- [ ] **B1.** In `src/network/net_sender.h`, declare `class ConnectionNetSender final : public INetSender { ... }` with:
  - constructor `(std::shared_ptr<con::IConnection> con, SessionRegistry &sessions)`.
  - `~ConnectionNetSender() override = default;`
  - `void send(session_t, const NetworkPacket &) final override;`
  - `void sendAll(const NetworkPacket &, ClientState min) final override;`
  - one private accessor `Session *sessionFor(session_t)` that consults `m_sessions` (the registry is **not** locked here — callers hold the registry lock or are in cold path; document this).
- [ ] **B2.** In `src/network/net_sender.cpp`, implement `ConnectionNetSender::send` as a one-liner forwarding to `m_con->Send(peer_id, pkt.getChannel(), const_cast<NetworkPacket*>(&pkt), pkt.isReliable())`. Mark `final` + `noexcept` to keep the compiler happy and the inlining clear.
- [ ] **B3.** Implement `ConnectionNetSender::sendAll` as: walk `m_sessions.getClientIDs(min)`, send to each via `send`. No new lock (the registry's recursive mutex is taken inside `getClientIDs`).
- [ ] **B4.** Add a unit test `unittest/test_connection_netsender_lowlevel.cpp` that:
  - constructs a `MockConnection` (subclass of `con::IConnection` with a `std::vector<RecordedSend> m_recorded;`),
  - constructs a `ConnectionNetSender` with that mock + a `SessionRegistry` containing 2 sessions,
  - calls `send` and asserts the recorded packet matches the input,
  - calls `sendAll` and asserts both sessions received it.
- [ ] **B5.** Confirm `benchmark/` reports no regression on a 1 M-packet loop through `ConnectionNetSender::send`.

### Phase C — Move the high-level `Server::Send*` bodies (≈ 1 week, mechanical)

- [ ] **C1.** In `src/network/net_sender.cpp`, paste **verbatim** the bodies of the 47 `Server::Send*` methods from `src/server.cpp`, replacing:
  - `this->m_clients.send(peer_id, &pkt)` → `m_con->Send(...)` (or, for sessions-aware variants, `send(peer_id, pkt)`).
  - `this->m_clients.sendToAll(&pkt, ...)` → `sendAll(pkt, ...)`.
  - `this->m_env->...` if any → kept as a parameter injected via constructor (e.g. `m_env` member of the sender, only for `SendBlockNoLock`-style methods).
- [ ] **C2.** Move the `m_env` member out of the `Server` for the duration of this phase: introduce a `WorldHooks &m_hooks` (later replaced by the real `WorldHooks` of step 5). For now, `Server` implements a minimal inline `WorldHooks` adapter that forwards to its own members. This keeps the refactor purely mechanical.
- [ ] **C3.** For each moved method, add the corresponding declaration on `INetSender` as a defaulted method (so `MockNetSender` inherits the no-op default — `MockNetSender` overrides only the low-level `send`). Mark each defaulted method `inline` and `noexcept` where possible.
- [ ] **C4.** Replace the 47 `Server::Send*` bodies in `src/server.cpp` with one-liners that forward to the appropriate `m_net_sender->sendXxx(...)` member. Do **not** delete the `Server::Send*` declarations yet (handlers still call them).
- [ ] **C5.** Build. Resolve any forward-declaration / include-order issues (likely: `INetSender` needs `NetworkPacket` complete type; `NetworkPacket` may need a `getChannel()` and `isReliable()` accessor — add if missing).
- [ ] **C6.** Run the existing unit test suite (`ctest`). All tests must pass with no behavior change.

### Phase D — Mock implementation + test harness (≈ 1–2 days)

- [ ] **D1.** Create `src/unittest/mock_net_sender.h` (header-only) with:
  - `struct SentRecord { session_t peer; u16 opcode; u8 channel; bool reliable; std::string payload; v3f pos; /* etc. */ };`
  - `class MockNetSender final : public INetSender { std::vector<SentRecord> sent; void send(session_t, const NetworkPacket &) final override; /* low-level: records */ /* high-level: defaulted from base */ };`
- [ ] **D2.** In `MockNetSender::send`, decode the packet's command and append a `SentRecord` (opcode via `pkt.getCommand()`, payload via `pkt.getRemainingString()`).
- [ ] **D3.** Provide helper assertions on `MockNetSender`:
  - `bool hasSent(session_t, u16 opcode) const;`
  - `size_t countSent(session_t, u16 opcode) const;`
  - `SentRecord lastSent(session_t, u16 opcode) const;`
- [ ] **D4.** Add `unittest/test_mock_netsender.cpp` that exercises the high-level defaulted methods: build a small `NetworkPacket`, call `sender.sendTimeOfDay(42, 1234, 1.0f)`, assert `hasSent(42, TOCLIENT_TIME_OF_DAY)` is true. Repeat for at least 5 different high-level methods.
- [ ] **D5.** Add `unittest/test_netsender_payloads.cpp` that round-trips a representative packet for each high-level method against the *current* `Server::Send*` body (compiled into a tiny shim) and the new `ConnectionNetSender` method — assert the wire bytes are identical (catch wire-format regressions early).

### Phase E — Replace callers (≈ 1 week, scoped)

- [ ] **E1.** Identify hot-path callers: `Server::Receive` → `ProcessData` → handlers (`handleCommand_*`). These still go through `Server::Send*` shims, which is fine. **No change here in this PR.**
- [ ] **E2.** Identify cold-path callers outside `Server`: e.g. `ServerEnvironment::SendActiveObjectMessages` indirectly via `m_server->SendActiveObjectMessages(...)`. These remain calling the `Server::` shim for now.
- [ ] **E3.** Identify Lua API surface: `l_server.cpp` and friends. They go through `Server::Send*` shims, which forward to the sender. **No Lua API change.**
- [ ] **E4.** The only direct caller of `m_con->Send(...)` in user code today is `Server::Send(NetworkPacket*)` and `Server::Send(session_t, NetworkPacket*)`. After this PR, these are the *only* two methods on `Server` that still touch `m_con` directly. Verify with `rg 'm_con->Send' src/`.
- [ ] **E5.** Add a comment in `server.h` above each remaining `Server::Send*` shim: `// TODO(refactor): migrate to INetSender in next phase`.

### Phase F — Performance validation (≈ half a day)

- [ ] **F1.** Add a microbenchmark `benchmark/benchmark_netsender.cpp` that:
  - constructs a `MockConnection` recording the `Send` call (no socket),
  - builds N=1 000 000 `NetworkPacket`s (small `TOCLIENT_TIME_OF_DAY`),
  - calls `ConnectionNetSender::send` for each,
  - measures throughput in packets/sec and ns/packet.
- [ ] **F2.** Run the same benchmark against the **old** code path (compile a small standalone binary that links `Server::Send`). Compare: assert `new_ns_per_pkt ≤ old_ns_per_pkt × 1.02` (2 % tolerance).
- [ ] **F3.** Run `ctest` under `tsan` and `asan` to catch new races/leaks.

### Phase G — Documentation & cleanup (≈ half a day)

- [ ] **G1.** Add a `doc/refactor/netsender.md` describing the interface, the two implementations, the migration strategy, and the test strategy. Reference §10.5 and §12 of this plan.
- [ ] **G2.** Update `doc/architecture.md` (if it exists) or `doc/server_architecture.md` to include `INetSender` in the dependency graph.
- [ ] **G3.** Mark the PR as `refactor / no-behavior-change / phase-2`. List the touched files in the description.

### Phase H — Risk gates (run before merging)

- [ ] **H1.** `cmake --build build && ctest --output-on-failure` — all green.
- [ ] **H2.** `benchmark_netsender` — within tolerance of baseline.
- [ ] **H3.** Manual smoke: launch a local server, connect a client, walk through the full login → place a block → disconnect flow. Confirm the network panel shows the same packet sequence as before the PR.
- [ ] **H4.** `tsan` and `asan` runs — clean.
- [ ] **H5.** `git grep 'm_con->Send'` — returns only the 2 expected sites (`Server::Send` and `Server::Send(session_t, NetworkPacket*)`).
- [ ] **H6.** `git grep 'Server::Send'` — at most the 47 expected shim definitions + their callers (no growth).

### Definition of Done (DoD)

* `INetSender` exists in `src/network/net_sender.h` with the high-level methods as defaulted.
* `ConnectionNetSender` is `final`, forwards to `m_con->Send` with no extra lock, and is on the hot path with measured ≤ 2 % overhead.
* `MockNetSender` exists, records all sends, and is used in at least 3 unit tests.
* All 47 `Server::Send*` methods still exist, but their bodies are one-line forwards to `m_net_sender`.
* No wire-format change (verified by `test_netsender_payloads.cpp`).
* `Server::Send(NetworkPacket*)` and `Server::Send(session_t, NetworkPacket*)` are the only direct callers of `m_con->Send` in the entire codebase.
* Benchmark, tsan, asan, ctest all clean.
* The next PR (phase 3: handlers via `ServerDispatcher`) can begin without blocking on this one.

---

## 13. Implementation plan for `Session` (PR #1 of §10.11)

### 13.1 Scope and goals

Deliver the **first** deliverable of §10.11. The end state:

* A new `Session` class in `src/server/session.h` / `src/server/session.cpp` that owns **all game-level per-peer state** currently split between `RemoteClient` (per-client cache) and the implicit `Server` lookups.
* A new `SessionRegistry` in `src/server/session_registry.h` / `src/server/session_registry.cpp` that owns the map of `Session` and the state-machine event distribution. Functionally equivalent to today's `ClientInterface`.
* `RemoteClient` and `ClientInterface` are kept as **thin aliases** (`using RemoteClient = Session;` and `using ClientInterface = SessionRegistry;`) for one release — this is what keeps the diff mechanical and the risk near zero.
* No behavior change, no wire-format change, no perf regression.

**Out of scope for this PR** (deferred to PRs #2, #3, #4):
* The `INetSender` interface (PR #2).
* The `ServerDispatcher` (PR #3).
* The `ServerContext` (PR #4).
* Wiring handlers to consume `Session&` instead of `session_t`.

The first three PRs are decoupled so they can ship in any order or in parallel.

### 13.2 Files to create

```
src/server/session.h            # ~250 lines: class Session, AuthSubState, OutgoingItem
src/server/session.cpp          # ~120 lines: state machine, getters/setters
src/server/session_registry.h   # ~150 lines: class SessionRegistry
src/server/session_registry.cpp # ~350 lines: port of clientiface.cpp methods
src/unittest/test_session.cpp   # ~300 lines: state machine + per-field tests
src/unittest/test_session_registry.cpp  # ~200 lines: lookup, send, broadcast, lifecycle
```

### 13.3 Files to modify (mechanical)

```
src/server/clientiface.h        # add `using RemoteClient = Session;` and `using ClientInterface = SessionRegistry;` at the bottom
src/server/clientiface.cpp      # remove the bodies of `RemoteClient::*` and `ClientInterface::*` that now live in Session*; leave a `#include "session.h"` and `session_registry.h` and forwarding definitions for the methods whose signatures must stay identical
src/server.h                    # no change (it already uses RemoteClient/ClientInterface by name)
src/server.cpp                  # no change at the call site (still uses m_clients.getClientNoEx etc., which are now SessionRegistry methods)
src/network/serverpackethandler.cpp  # no change (same aliases)
src/script/lua_api/l_server.cpp # no change (same aliases)
```

### 13.4 Design — `Session`

#### 13.4.1 Header shape

```cpp
// src/server/session.h
#pragma once

#include "clientiface.h"          // brings ClientState, ClientStateEvent for the alias
#include "constants.h"            // PEER_ID_INEXISTENT
#include "network/address.h"      // Address
#include "irr_v3d.h"              // v3s16
#include "util/auth.h"            // AuthMechanism
#include "mapblock.h"             // SerializedBlockCache

#include <memory>
#include <string>
#include <string_view>
#include <unordered_set>
#include <unordered_map>
#include <deque>

class PlayerSAO;
class NetworkPacket;
class ServerEnvironment;

/**
 * Per-peer game state. One instance per connected peer, owned by
 * SessionRegistry. Not thread-safe on its own; the registry's recursive
 * mutex is the single source of locking.
 */
class Session {
public:
    // --- Construction / destruction ----------------------------------
    Session(session_t id, const Address &addr, ClientState initial = CS_Created);
    ~Session();

    Session(const Session &) = delete;
    Session &operator=(const Session &) = delete;

    // --- Identity ----------------------------------------------------
    session_t        id()           const { return m_id; }
    const Address   &address()      const { return m_addr; }
    u64              uptime()       const;          // port from RemoteClient
    const std::string &name()       const { return m_name; }
    void             setName(std::string n);

    // --- State machine -----------------------------------------------
    ClientState      state()        const { return m_state; }
    void             notifyEvent(ClientStateEvent evt);  // port from RemoteClient::notifyEvent

    // --- Player / SAO linkage ----------------------------------------
    PlayerSAO       *player()       const { return m_player; }
    void             attachPlayer(PlayerSAO *sao);
    void             detachPlayer();

    // --- Per-session caches (verbatim from RemoteClient) ------------
    SerializedBlockCache                block_cache;
    std::unordered_set<v3s16>           blocks_sent;
    std::unordered_set<v3s16>           blocks_sending;
    std::unordered_set<v3s16>           blocks_occ;
    std::unordered_set<std::string>     media_sent;
    std::set<u16>                       known_objects;
    std::string                         formspec_state;
    std::string                         lang_code;

    // --- Versioning ---------------------------------------------------
    u8   serialization_version         = SER_FMT_VER_INVALID;
    u8   pending_serialization_version = SER_FMT_VER_INVALID;
    u16  net_proto_version             = 0;
    void setPendingSerializationVersion(u8 v) { m_pending_serialization_version = v; }
    void confirmSerializationVersion()       { serialization_version = m_pending_serialization_version; }

    // --- Auth state (typed; opaque void* stays only in alias bridge) -
    AuthMechanism chosen_mech            = AUTH_MECHANISM_NONE;
    u32           allowed_auth_mechs     = 0;
    std::string   enc_pwd;
    bool          create_player_on_auth_success = false;

    // SRP: opaque handle kept as raw ptr for one release (same as today);
    // resetChosenMech() owns the lifetime.
    void         *auth_data              = nullptr;
    void          resetChosenMech();           // frees auth_data, resets chosen_mech
    void          setEncryptedPassword(const std::string &pwd);

    // --- Build/connection-time fields (from RemoteClient) -----------
    float m_time_from_building            = 9999.f;
    float m_nothing_to_send_pause_timer   = 0.0f;
    float m_map_send_completion_timer     = 0.0f;
    s16   m_nearest_unsent_d              = 0;
    v3s16 m_last_center                   = v3s16(0,0,0);
    v3f   m_last_camera_dir               = v3f(0,0,1);
    u8    m_version_major                 = 0;
    u8    m_version_minor                 = 0;
    u8    m_version_patch                 = 0;
    std::string m_full_version            = "unknown";
    u32   m_excess_gotblocks              = 0;
    u16   m_max_simul_sends               = 0;
    float m_min_time_from_building        = 0.f;
    s16   m_max_send_distance             = 0;
    s16   m_block_optimize_distance       = 0;
    s16   m_block_cull_optimize_distance = 0;
    s16   m_max_gen_distance              = 0;
    bool  m_occ_cull                      = false;
    u64   m_connection_time               = 0;

    // --- Block send helpers (port from RemoteClient) ----------------
    void GetNextBlocks(ServerEnvironment *env, EmergeManager *emerge,
                       float dtime, std::vector<PrioritySortedBlockTransfer> &dest);
    void GotBlock(v3s16 p);
    void SentBlock(v3s16 p);
    void SetBlockNotSent(v3s16 p, bool low_priority = false);
    void SetBlocksNotSent(const std::vector<v3s16> &blocks, bool low_priority = false);
    void ResendBlockIfOnWire(v3s16 p);

    // --- Misc (verbatim port) ----------------------------------------
    void setVersionInfo(u8 major, u8 minor, u8 patch, const std::string &full);
    void setLangCode(const std::string &code);
    const std::string &getLangCode() const { return m_lang_code; }
    const std::string &getFullVer()  const { return m_full_version; }
    u8  getMajor() const { return m_version_major; }
    u8  getMinor() const { return m_version_minor; }
    u8  getPatch() const { return m_version_patch; }
    const Address &getAddress() const { return m_addr; }
    void setCachedAddress(const Address &a) { m_addr = a; }
    ClientDynamicInfo &dynamicInfo() { return m_dynamic_info; }
    const ClientDynamicInfo &dynamicInfo() const { return m_dynamic_info; }
    void PrintInfo(std::ostream &o) const;

    // --- Outbox (used by the future PR #2/3; no-op for this PR) -----
    struct OutgoingItem {
        std::unique_ptr<NetworkPacket> pkt;
        u8   channel;
        bool reliable;
    };
    void enqueueOutgoing(std::unique_ptr<NetworkPacket> pkt, u8 channel, bool reliable);
    // Implementation in PR #2; for now, sends immediately to a no-op sender.
    void flushOutgoing();   // empty in this PR

private:
    const session_t  m_id;
    Address          m_addr;
    ClientState      m_state = CS_Created;
    PlayerSAO       *m_player = nullptr;
    ClientDynamicInfo m_dynamic_info{};
    std::string      m_name;
    std::deque<OutgoingItem> m_outbox;  // unused in this PR, kept for layout stability
};
```

**Key design decisions**:
1. **All members are public** for now — this preserves the field-access patterns used everywhere in the codebase (`client->m_blocks_sending`, `client->serialization_version`, etc.). In PR #4 we will progressively move them behind accessors.
2. **The `peer_id` field is removed** — `m_id` replaces it. The alias `RemoteClient::peer_id` becomes a static_cast or a getPeerId() helper. Cleanest: keep `peer_id` as a back-pointer in the alias header (see §13.4.3).
3. **The `enqueueOutgoing`/`flushOutgoing` are stubs in this PR.** They take the right signature so future PRs can wire them without changing the public API. They do not allocate or do anything in PR #1.
4. **`m_addr` is updated by `setCachedAddress` exactly like today's `RemoteClient::setCachedAddress`.** The ctor takes the initial address (from `con::IPeer::getAddress()`), and `setCachedAddress` is called later by `handleCommand_Init` after the peer is fully identified.
5. **The state machine is `Session::notifyEvent` — moved verbatim from `RemoteClient::notifyEvent`** (`src/server/clientiface.cpp:465-612`). No logic change, no transitions added or removed.

#### 13.4.2 Implementation notes (`.cpp`)

* **Ctor body** (port from `RemoteClient::RemoteClient`, `clientiface.cpp:57-71`):
  * Initialize the 7 settings-derived fields (`m_max_simul_sends`, `m_min_time_from_building`, etc.) via `g_settings->getXxx(...)` (same as today).
  * Set `m_connection_time = porting::getTimeS()`.
  * `m_state = initial` (default `CS_Created`).
* **`notifyEvent`** is **a verbatim copy** of `RemoteClient::notifyEvent` (`clientiface.cpp:465-612`), with `m_state` instead of the implicit `this->m_state`. No edits.
* **`resetChosenMech`** and **`setEncryptedPassword`**: verbatim ports.
* **`uptime`**: `porting::getTimeS() - m_connection_time`.
* **`setName`**: assign `m_name = std::move(n)`. No sanitization (today the name is sanitized in the handler, not the setter).
* **`setVersionInfo` / `setLangCode` / `PrintInfo` / `PrintInfo`**: verbatim ports with the `string_sanitize_ascii` helper moved into `session.cpp` (static, anonymous namespace).
* **Block methods (`GetNextBlocks` / `GotBlock` / `SentBlock` / `SetBlockNotSent` / `SetBlocksNotSent` / `ResendBlockIfOnWire`)**: verbatim ports of `clientiface.cpp:73-463`. No logic change.

#### 13.4.3 The `RemoteClient` alias

`clientiface.h` ends with:

```cpp
// --- Compatibility aliases (deprecated, to be removed in PR #5) ---
#include "session.h"
class RemoteClient : public Session {
public:
    using Session::Session;
    // Restore the historical field name for old code.
    session_t peer_id;   // shadows Session::id() with a mutable field — see note
};
// Note: in PR #1 we keep the `peer_id` field mutable. We do NOT add an
// override for id(): callers using `client->peer_id` keep working.
// To avoid double-storage, RemoteClient's ctor sets `peer_id` from the
// base's `m_id` in a default member initializer? No — `m_id` is private.
// Instead, RemoteClient overrides `id()` to return peer_id.
```

**Wait — this creates a footgun.** The cleanest way is to make `peer_id` a *getter* on `RemoteClient` that returns the same value as `Session::id()`:

```cpp
class RemoteClient : public Session {
public:
    using Session::Session;
    // Field used by ~80 sites that do `client->peer_id`.
    // We expose it as an lvalue by binding a reference to the result of id().
    // Unfortunately C++ doesn't allow lvalue references to temporaries,
    // so we need a different strategy: introduce a mutable `peer_id` field
    // in RemoteClient, set it in the ctor, and have RemoteClient::id() return
    // that field instead of the base.
    session_t peer_id = PEER_ID_INEXISTENT;
    session_t id() const override { return peer_id; }
};
```

Then `RemoteClient`'s constructor (inherited from `Session`) takes `(session_t, Address, ClientState)`. The constructor body of `RemoteClient` sets `peer_id = id;`. **All call sites that use `client->peer_id` keep working.** All call sites that used `client->m_known_objects` etc. now use `client->known_objects` (the field on `Session`) — but since `RemoteClient` inherits from `Session` publicly, the field is accessible unchanged.

There are two call sites that *write* to `peer_id`:
* `ClientInterface::CreateClient` (`clientiface.cpp:866-868`): `client->peer_id = peer_id;`
* `RemoteClient::RemoteClient()`: implicit.

Both are trivial: `CreateClient` becomes a no-op for `peer_id` (the `Session` ctor already took the id), and the `RemoteClient` ctor does `peer_id = id;` in a member initializer list (or `{ peer_id(id) {} }`).

#### 13.4.4 The `ClientInterface` alias

```cpp
class ClientInterface : public SessionRegistry {
public:
    using SessionRegistry::SessionRegistry;
    // Legacy methods that are *not* on SessionRegistry as-is must be re-exposed.
    // ... (see §13.5)
};
```

### 13.5 Design — `SessionRegistry`

#### 13.5.1 Header shape

```cpp
// src/server/session_registry.h
#pragma once

#include "clientiface.h"             // ClientState, ClientStateEvent
#include "constants.h"               // PEER_ID_INEXISTENT
#include "network/address.h"
#include "session.h"
#include "threading/mutex_auto_lock.h"

#include <memory>
#include <unordered_map>
#include <vector>

class NetworkPacket;
namespace con { class IConnection; }

class SessionRegistry {
public:
    using AutoLock = RecursiveMutexAutoLock;

    explicit SessionRegistry(const std::shared_ptr<con::IConnection> &con);
    ~SessionRegistry();

    // --- Transport -> Session lifecycle ------------------------------
    Session &onPeerAdded(session_t id, const Address &addr);
    void     onPeerRemoved(session_t id, bool timeout);

    // --- Lookup (lock taken internally) ------------------------------
    Session *getClientNoEx(session_t peer_id, ClientState state_min = CS_Active);
    Session *lockedGetClientNoEx(session_t peer_id, ClientState state_min = CS_Active);
    ClientState getClientState(session_t peer_id);
    u16         getProtocolVersion(session_t peer_id);

    // --- Iteration (lock taken internally) ---------------------------
    std::vector<session_t> getClientIDs(ClientState min_state = CS_Active);
    std::vector<Session*>& getClientList();
    const std::vector<std::string> &getPlayerNames() const { return m_clients_names; }

    // --- Send --------------------------------------------------------
    void send(session_t peer_id, NetworkPacket *pkt);
    void sendCustom(session_t peer_id, u8 channel, NetworkPacket *pkt, bool reliable);
    void sendToAll(NetworkPacket *pkt, ClientState state_min = CS_Active);

    // --- State machine -----------------------------------------------
    void event(session_t peer_id, ClientStateEvent event);

    // --- Per-step ----------------------------------------------------
    void step(float dtime);

    // --- Misc --------------------------------------------------------
    void markBlocksNotSent(const std::vector<v3s16> &positions, bool low_priority = false);
    bool isUserLimitReached();
    void setEnv(ServerEnvironment *env);  // for UpdatePlayerList, the only env touch

protected:
    AutoLock lock() { return AutoLock(m_clients_mutex); }
    // Friend so Server can call into internals (kept for this PR; removed in #4).
    friend class Server;

private:
    void UpdatePlayerList();
    void deleteClient(session_t peer_id);

    std::shared_ptr<con::IConnection> m_con;
    mutable std::recursive_mutex      m_clients_mutex;
    std::unordered_map<session_t, std::unique_ptr<Session>> m_clients;
    std::vector<std::string>          m_clients_names;
    ServerEnvironment                *m_env = nullptr;
    float                             m_print_info_timer = 0;
    float                             m_check_linger_timer = 0;
    static constexpr int              LINGER_TIMEOUT = 12;
};
```

**Field-level diff with `ClientInterface`**:

| `ClientInterface` field | `SessionRegistry` field | Note |
|---|---|---|
| `m_con` (shared_ptr) | `m_con` (shared_ptr) | identical |
| `m_clients_mutex` (recursive_mutex) | `m_clients_mutex` (recursive_mutex) | identical |
| `m_clients` (`unordered_map<u16, RemoteClient*>`) | `m_clients` (`unordered_map<u16, unique_ptr<Session>>`) | ownership moves from `ClientInterface` (who `delete`s) to `unique_ptr` (RAII). No `DeleteClient` need to manually `delete` anymore. |
| `m_clients_names` | `m_clients_names` | identical |
| `m_env` (raw ptr, nullable) | `m_env` (raw ptr, nullable) | identical |
| `m_print_info_timer`, `m_check_linger_timer`, `LINGER_TIMEOUT` | identical | unchanged |

**Method-level diff**: every method on `ClientInterface` gets ported verbatim. Two adjustments:

* `CreateClient` becomes `onPeerAdded` and constructs a `std::make_unique<Session>(id, addr, CS_Created)`.
* `DeleteClient` becomes `onPeerRemoved` and calls `m_clients.erase(peer_id)` (the `unique_ptr` deletes automatically). The known-objects decrement loop (`clientiface.cpp:842-849`) is preserved as a private helper `deleteClient`.

**State machine entry point**: `event(peer_id, evt)` is the renamed `ClientInterface::event`, with one internal change: it calls `session->notifyEvent(evt)` instead of `client->notifyEvent(evt)`. The `UpdatePlayerList()` call on the terminal events is preserved.

#### 13.5.2 Implementation notes (`.cpp`)

* **No behavior changes.** The bodies of `getClientNoEx`, `lockedGetClientNoEx`, `send`, `sendToAll`, `sendCustom`, `event`, `step`, `UpdatePlayerList`, `markBlocksNotSent`, `isUserLimitReached`, `CreateClient`, `DeleteClient`, `getClientIDs`, `getClientState`, `getProtocolVersion` are **copied verbatim** from `clientiface.cpp:672-905`, with two edits per function:
  * `RemoteClient *` → `Session *`.
  * `delete m_clients[peer_id]; m_clients.erase(peer_id);` → `m_clients.erase(peer_id);` (the unique_ptr deletes).
  * `client->peer_id` → `client->id()` (in code paths that use it as a value, e.g. `client_it.second->peer_id` in iteration → `client_it.second->id()`).
* The `friend class Server;` declaration is necessary because `Server::peerAdded` and `Server::deletingPeer` need to call `onPeerAdded` / `onPeerRemoved`. In PR #4 we will replace the friend with explicit `IServerLifecycle` interface.
* The `AutoLock` alias is provided for callers that use it (e.g. `Server::AsyncRunStep` uses `ClientInterface::AutoLock`). Removing it would touch ~10 sites; aliasing is cheaper.

#### 13.5.3 The `RemoteClientMap` typedef

`RemoteClientMap` is used in 4 sites (`src/server/clientiface.h:428`, `src/server.cpp:864, 933`). It maps `u16 → RemoteClient*`. The new `SessionRegistry` owns `unique_ptr`, so `RemoteClientMap` cannot be a `std::unordered_map<u16, RemoteClient*>` anymore. Two options:

* **Option A (recommended):** keep `RemoteClientMap` as the type `std::unordered_map<u16, RemoteClient*> &` returned by `SessionRegistry::getClientList()`. To produce a `RemoteClientMap &` from a `unique_ptr`-owned map, expose a parallel `std::unordered_map<u16, RemoteClient*> m_clients_view` that is rebuilt on `onPeerAdded`/`onPeerRemoved`. **Cost: O(N) on each add/remove, but only the 2 `server.cpp` sites iterate it during map-edit events, which are not on the hot path.** Simpler alternative: change the 2 call sites to iterate over the `unique_ptr` map directly. Recommended (see below).
* **Option B:** change the 2 call sites to iterate over `m_clients` (the `unique_ptr` map). The diff is local and explicit.

**Recommendation: option B.** The 2 call sites in `server.cpp:864-947` are:
```cpp
const RemoteClientMap &clients = m_clients.getClientList();
for (const auto &client_it : clients) {
    RemoteClient *client = client_it.second;
    // ...
}
```
Becomes:
```cpp
const auto &clients = m_clients.getClientList();
for (const auto &client_it : clients) {
    Session *client = client_it.second.get();
    // ...
}
```

Where `SessionRegistry::getClientList()` returns `const std::unordered_map<u16, std::unique_ptr<Session>> &`.

**`RemoteClientMap` typedef** stays as a deprecated alias:
```cpp
// in clientiface.h, for one release
using RemoteClientMap = std::unordered_map<u16, RemoteClient*>;
```
**It will be a different type** from `SessionRegistry::m_clients` after the refactor. We must update the 2 call sites. To make this safe, the type alias points to the *old* layout, and `getClientList()` returns a different (correct) type. Compiler errors will pinpoint the 2 sites that need updating.

### 13.6 CMake changes

`src/server/CMakeLists.txt` (or wherever the existing sources are listed) gains:
```cmake
src/server/session.h
src/server/session.cpp
src/server/session_registry.h
src/server/session_registry.cpp
```
`src/unittest/CMakeLists.txt` gains:
```cmake
unittest/test_session.cpp
unittest/test_session_registry.cpp
```

### 13.7 Testing strategy

#### 13.7.1 Unit tests for `Session` (`test_session.cpp`)

| Test | What it verifies |
|---|---|
| `test_construction_defaults` | `Session{42, addr}` has `state() == CS_Created`, `name() == ""`, `serialization_version == SER_FMT_VER_INVALID`, all the settings-derived fields match `g_settings`. |
| `test_setter_chains` | `setName("bob")` → `name() == "bob"`. `setVersionInfo(1,2,3,"1.2.3")` → getters return them. `setLangCode("fr")` → sanitized. |
| `test_state_machine_created_to_hello` | `notifyEvent(CSE_Hello)` → `state() == CS_HelloSent`. |
| `test_state_machine_active_to_disconnect` | `notifyEvent(CSE_Disconnect)` from any of `CS_Created/CS_HelloSent/CS_AwaitingInit2/CS_InitDone/CS_DefinitionsSent/CS_Active/CS_SudoMode` → `state() == CS_Disconnecting`. |
| `test_state_machine_illegal_transitions_throw` | `notifyEvent(CSE_AuthAccept)` from `CS_Created` throws `ClientStateError`. Cover every illegal pair from the current switch (`clientiface.cpp:467-611`). |
| `test_state_machine_sudo_roundtrip` | `CS_Active` + `CSE_SudoSuccess` → `CS_SudoMode`; `CS_SudoMode` + `CSE_SudoLeave` → `CS_Active`. |
| `test_reset_chosen_mech_frees_auth_data` | Allocate an `auth_data` stub (the test uses a custom deleter in a child class? — or just inject a sentinel and call `resetChosenMech`; the SRP free is hard to test without a real verifier; **test the field reset only**). |
| `test_block_helpers` | `GotBlock(x)` moves `x` from `blocks_sending` to `blocks_sent`. `SetBlockNotSent(x)` removes from both. `ResendBlockIfOnWire` no-op when not sending. |
| `test_getnextblocks_needs_player` | Without a player in the env, `GetNextBlocks` returns 0 results. (Smoke test only; full coverage of the algorithm is in `test_moveaction.cpp`.) |

All tests use a minimal `ServerEnvironment` substitute (a `TestServerEnvironment` that just implements `getPlayer(peer_id) -> nullptr`); for the `GetNextBlocks` test, an env that returns a `RemotePlayer` with a `PlayerSAO` is needed. The `MockPlayerSAO` is already present in `unittest/mock_serveractiveobject.h`; the env stub can be 30 lines.

#### 13.7.2 Unit tests for `SessionRegistry` (`test_session_registry.cpp`)

| Test | What it verifies |
|---|---|
| `test_peer_added_creates_session` | After `onPeerAdded(42, addr)`, `getClientNoEx(42)` returns a non-null `Session` with `state() == CS_Created` and `address() == addr`. |
| `test_peer_removed_erases_session` | After `onPeerRemoved(42, false)`, `getClientNoEx(42)` returns `nullptr`. |
| `test_event_drives_state` | `event(42, CSE_Hello)` followed by `getClientState(42) == CS_HelloSent`. |
| `test_getclientids_respects_min_state` | Add 3 sessions, advance 2 to `CS_Active`, then `getClientIDs(CS_Active).size() == 2`. |
| `test_send_to_all_uses_clientcommandfactory` | Mock `con::IConnection` records sends; `sendToAll(&pkt, CS_Active)` causes exactly the active clients to receive a `Send(peer, channel, pkt, reliable)` call with the channel/reliability from `clientCommandFactoryTable`. |
| `test_send_to_unknown_peer_logs` | `send(999, &pkt)` does not crash and is a no-op (matches today's behavior, which silently no-ops). |
| `test_step_lingers_old_clients` | Set `m_check_linger_timer = 1.0f`; advance a session's `uptime()` past `LINGER_TIMEOUT`; `step(1.0f)` calls `m_con->DisconnectPeer(peer_id)`. Use a `MockConnection` that records `DisconnectPeer` calls. |
| `test_step_does_not_linger_init_done` | Same setup but with `state >= CS_InitDone`; `DisconnectPeer` is NOT called. |
| `test_update_player_list_collects_names` | With an env stub that returns 2 players, `step(30.0f)` (to trigger `UpdatePlayerList`) results in `getPlayerNames()` of size 2. |
| `test_user_limit` | `isUserLimitReached()` returns true when `max_users` is reached. |
| `test_mark_blocks_not_sent` | For each active client, calls `SetBlocksNotSent(positions)`. |
| `test_concurrent_lookup_under_contention` | (Optional, for thread-safety verification.) Two threads: one does 10 k `getClientNoEx`, another does 1 k `onPeerAdded/onPeerRemoved`. Run under `tsan`. |

### 13.8 Migration / merge plan (sub-PRs for safer review)

The change is large but mechanical. Split it into 3 stacked PRs that each leave the tree compiling and tests green:

#### PR #1.1 — Add the new files, no callers updated (~half a day, no behavior change)

- [ ] Create `src/server/session.h` with the full class declaration.
- [ ] Create `src/server/session.cpp` with all method bodies ported **verbatim** from `clientiface.cpp` (with `RemoteClient` renamed to `Session` and `peer_id` reads replaced by `id()`).
- [ ] Add to `src/server/CMakeLists.txt`.
- [ ] Build. No new compilation unit is *used* yet, so nothing should break.
- [ ] Add `src/unittest/test_session.cpp` with all the unit tests in §13.7.1. They construct `Session` directly.
- [ ] Run `ctest` — all green.

#### PR #1.2 — Add `SessionRegistry` and the aliases (~1 day, no behavior change)

- [ ] Create `src/server/session_registry.h` and `.cpp` with the bodies ported from `clientiface.cpp:649-905`. **Important:** `SessionRegistry::m_clients` uses `std::unique_ptr<Session>`.
- [ ] Add the two `using` aliases at the bottom of `src/server/clientiface.h`:
  ```cpp
  #include "session.h"
  class RemoteClient : public Session {
  public:
      using Session::Session;
      session_t peer_id;
  };
  #include "session_registry.h"
  using ClientInterface = SessionRegistry;
  ```
- [ ] In `clientiface.cpp`, delete the bodies of every method that has been ported to `Session` or `SessionRegistry` (i.e. all the bodies in `clientiface.cpp` except the small `RemoteClient::RemoteClient` ctor and the small `ClientInterface::{ClientInterface,~ClientInterface}` ctors). **Replace** them with inline forwarders that simply call the corresponding `Session` / `SessionRegistry` method. The forwarders exist only to keep ABI/source compatibility; they will be removed in PR #5.
- [ ] The 2 call sites in `src/server.cpp` that iterate `m_clients.getClientList()` change to iterate the new `unique_ptr` map (option B in §13.5.3).
- [ ] `RemoteClientMap` typedef is changed: it now points to a **type that no longer matches `m_clients`**. The 2 call sites must be updated; the compiler will guide us.
- [ ] Add `src/unittest/test_session_registry.cpp` with the tests in §13.7.2.
- [ ] Run `ctest` + `tsan` + `asan` — all green.

#### PR #1.3 — Remove forwarders, add benchmark, polish (~half a day)

- [ ] Delete the forwarder bodies in `clientiface.cpp`. The `RemoteClient` ctor body sets `peer_id = id;` in an initializer list.
- [ ] Add a microbenchmark `benchmark/benchmark_session_lookup.cpp`: 1 M random `SessionRegistry::getClientNoEx` lookups across 64 sessions. Assert ≤ 2 % regression vs. `ClientInterface::getClientNoEx` baseline.
- [ ] Update `doc/architecture.md` (or create `doc/server_architecture.md`) with a one-page diagram of `Server / SessionRegistry / Session / RemoteClient` and a note that `RemoteClient`/`ClientInterface` are deprecated aliases.
- [ ] Mark `RemoteClient::peer_id` and `ClientInterface::*` as `[[deprecated]]` with a comment pointing to the new types.

### 13.9 Risk gates (run before merging each sub-PR)

- [ ] `cmake --build build` — clean.
- [ ] `ctest --output-on-failure` — all green, including the existing `test_moveaction.cpp`, `test_server_shutdown_state.cpp`, `test_sao.cpp`, `test_serveractiveobjectmgr.cpp`.
- [ ] `tsan` run — clean.
- [ ] `asan` run — clean.
- [ ] `rg -n 'RemoteClient' src/` — only the alias definitions + the 2 sites in `server.cpp` that read `client->peer_id`. No growth.
- [ ] `rg -n 'm_clients\.' src/` — same set of call sites as before.
- [ ] `rg -n 'ClientInterface' src/` — only the alias definition.
- [ ] `benchmark/benchmark_session_lookup.cpp` — within 2 % of baseline.
- [ ] Manual smoke: launch a local server, connect 2 clients, log in, place blocks, disconnect, reconnect.

### 13.10 Definition of Done (PR #1 as a whole)

* `Session` exists in `src/server/session.{h,cpp}` with all state machine and per-peer state.
* `SessionRegistry` exists in `src/server/session_registry.{h,cpp}` with all map-management and send helpers.
* `RemoteClient` is a deprecated alias (`class RemoteClient : public Session`).
* `ClientInterface` is a deprecated alias (`using ClientInterface = SessionRegistry`).
* The 53+ call sites that use `m_clients.*` and `client->...` continue to work without edits (except the 2 `getClientList()` iteration sites, which are mechanical).
* No new lock taken on the hot path. `SessionRegistry` uses the same `std::recursive_mutex` as `ClientInterface`.
* The hot-path lookup (`m_clients.getClientNoEx(peer_id, state_min)`) is a hashmap lookup under a recursive mutex, with the same algorithmic complexity as today.
* `test_session.cpp` and `test_session_registry.cpp` are present and pass under `tsan`/`asan`.
* Benchmark shows ≤ 2 % overhead vs. baseline.
* No wire-format change. No protocol change. No Lua API change. No DB format change.
* The next PR (PR #2: `INetSender`) can begin without blocking on this one.

### 13.11 Open questions to validate with the user

1. **`RemoteClient::peer_id` field**: keep it as a public mutable field on the alias, with `Session::id()` reading through it (as proposed in §13.4.3), or take the small extra churn of updating all 80+ reads to use `client->id()` directly? Recommendation: keep the field for this PR (minimum diff), remove it in PR #5.
2. **`Session::enqueueOutgoing` / `flushOutgoing`**: include them as no-op stubs in PR #1 (recommended, for API stability), or defer them to PR #2? Recommendation: include as no-op stubs.
3. **Removing forwarders vs. keeping them**: §13.8 PR #1.3 removes the forwarders. Should we keep the `RemoteClient::xxx()` method bodies as one-line `Session::xxx()` forwarders for one release (safer, more diff) or delete them now (cleaner, but a longer PR review)? Recommendation: delete them in #1.3; the 80+ call sites don't need them since they call through `m_clients.*` and `client->...` directly.
4. **`m_clients` ownership change** (`RemoteClient*` → `unique_ptr<Session>`): this is a real semantic change (RAII deletion). It is also the entire point of the refactor (no manual `delete` in `DeleteClient`). Confirm we want this in PR #1.

