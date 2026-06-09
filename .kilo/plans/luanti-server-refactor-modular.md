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
| `IServerServices` (facade) | Regroups services exposed to handlers: `IPlayerSvc`, `IWorldSrv`, `IAuthService`, `IBanService`, `IMediaService`, `IMetricsService`, `INotificationService`. | `Server` (API methods) | Yes (mocks) |
| `PlayerService` (impl) | Privs, kick, forms, hp/breath, hud, eye/sky/sun/moon/stars/clouds, fov, hotbar, animations, formspec state. | `Server::kickAllPlayers`, `notify*`, `hud*`, `setSky*`, `SendPlayerHP`, etc. | Yes, injecting a `RemotePlayer` and a fake `INetSender`. |
| `WorldService` (impl) | Environment step, block sending, ABM/LBM, particles, modchannels, time-of-day. | `Server::AsyncRunStep`, `SendBlocks`, `SendSpawnParticles`, `ServerEnvironment::step`. | Yes, injecting a test `ServerEnvironment`. |
| `AuthService` | SRP-first/second/M wrapper, acceptAuth, deny, sudo. | `Server::handleCommand_FirstSrp/SrpBytesA/SrpBytesM`, `acceptAuth`, `DenyAccess`. | Yes, mocking `IAuthDatabase`. |
| `BanService` | Ban/unban/description, deny-if-banned. | `Server::BanManager` (raw ptr) + methods. | Yes. |
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
