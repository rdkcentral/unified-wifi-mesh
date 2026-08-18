# Unified Wi-Fi Mesh architecture

This editable component diagram covers the `unified-wifi-mesh` subproject.
It uses [Mermaid](https://mermaid.js.org/), so GitHub and many Markdown
editors can render it directly. Edit the labels and connections in the fenced
`mermaid` block to keep it current.

```mermaid
flowchart TB
    subgraph EntryPoints[Entry points]
        CtrlBin["onewifi_em_ctrl<br/>Controller process"]
        AgentBin["onewifi_em_agent<br/>Agent process"]
        Cli["CLI / RDK-B CLI"]
    end

    subgraph Roles[Controller and agent]
        Ctrl["em_ctrl_t<br/>controller manager"]
        Agent["em_agent_t<br/>agent manager"]
        CtrlOrch["em_orch_ctrl_t<br/>controller orchestration"]
        AgentOrch["em_orch_agent_t<br/>agent orchestration"]
        CtrlCmd["em_cmd_ctrl_t<br/>controller command executor"]
        AgentCmd["em_cmd_agent_t<br/>agent command executor"]

        Ctrl --> CtrlOrch --> CtrlCmd
        Agent --> AgentOrch --> AgentCmd
    end

    CtrlBin --> Ctrl
    AgentBin --> Agent
    Cli --> CtrlCmd

    subgraph Commands[Commands and EasyMesh functions]
        Cmd["em_cmd_t<br/>command model"]
        Functions["EasyMesh protocol functions"]
        Discovery["Discovery"]
        Capability["Capability"]
        Channel["Channel selection"]
        Policy["Policy configuration"]
        Provisioning["Provisioning / DPP"]
        Steering["Client steering"]
        Metrics["Metrics"]

        Cmd --> Functions
        Functions --> Discovery & Capability & Channel & Policy
        Functions --> Provisioning & Steering & Metrics
    end

    CtrlCmd --> Cmd
    AgentCmd --> Cmd

    subgraph Data[Data and integration]
        DataModel["dm_easy_mesh_*<br/>network, device, radio, BSS, STA,<br/>policy, scan and MLO data"]
        Database["db_easy_mesh / db_client<br/>persistent data access"]
        TR181["TR-181 adapter"]
        OneWifi["OneWifi callbacks"]

        DataModel <--> Database
        TR181 <--> DataModel
        OneWifi <--> DataModel
    end

    CtrlOrch <--> DataModel
    AgentOrch <--> DataModel
    Cmd <--> DataModel

    subgraph Transport[AL-SAP transport]
        ALSAP["al_service_access_point<br/>AL-SAP endpoint"]
        Registration["Service registration"]
        SDU["al_service_data_unit<br/>1905 data unit"]
        Ethernet["Ethernet / IEEE 1905 network"]

        ALSAP --> Registration
        ALSAP <--> SDU
        SDU <--> Ethernet
    end

    Functions <--> ALSAP

    subgraph Support[Supporting modules]
        Crypto["Crypto utilities"]
        Optimiser["Network optimiser"]
        Utils["Utilities / JSON helpers"]
    end

    Provisioning --> Crypto
    Functions --> Optimiser
    Cmd --> Utils
```

## Source map

| Diagram area | Source locations |
| --- | --- |
| Controller and agent entry points | `src/ctrl/`, `src/agent/` |
| Commands and orchestration | `src/cmd/`, `src/orch/`, `inc/em_cmd*.h`, `inc/em_orch*.h` |
| EasyMesh protocol functions | `src/em/{disc,capability,channel,policy_cfg,prov,steering,metrics}/` |
| Data model and persistence | `src/dm/`, `src/db/`, `inc/dm_*.h`, `inc/db_*.h` |
| TR-181 and OneWifi integration | `src/ctrl/tr_181/`, `inc/tr_181.h`, `inc/em_onewifi.h` |
| AL-SAP / IEEE 1905 transport | `src/al-sap/`, `inc/al_service_*.h` |
| CLI and utilities | `src/cli/`, `src/rdkb-cli/`, `src/utils/`, `src/util_crypto/` |

## Controller-only view

This view isolates the controller process and the work it coordinates. It is
useful when tracing a CLI or management request through controller logic to an
IEEE 1905 message.

```mermaid
flowchart LR
    Cli["CLI / RDK-B CLI"] --> CtrlBin["onewifi_em_ctrl"]
    CtrlBin --> Ctrl["em_ctrl_t<br/>controller manager"]
    Ctrl --> Orch["em_orch_ctrl_t<br/>controller orchestration"]
    Orch --> Executor["em_cmd_ctrl_t<br/>controller command executor"]
    Executor --> Command["em_cmd_t<br/>command model"]

    Command --> Functions["EasyMesh functions"]
    Functions --> Discovery["Discovery and topology"]
    Functions --> Channel["Channel selection"]
    Functions --> Policy["Policy and configuration"]
    Functions --> Steering["Client steering and metrics"]
    Functions <--> ALSAP["AL-SAP<br/>IEEE 1905 transport"]
```

Relevant sources: `src/ctrl/`, `src/orch/`, `src/cmd/`, and
`src/em/`.

## Controller and database view

This view shows the controller's in-memory data model, its per-entity database
adapters, and its MariaDB-backed persistence path. The model owns a
`db_client_t` instance; each list type also implements `db_easy_mesh_t`, which
maps an EasyMesh entity to a database table and its columns. OneWifi callbacks
are agent-side and are intentionally omitted here.

```mermaid
flowchart TB
    subgraph Controller[Controller process: onewifi_em_ctrl]
        Ctrl["em_ctrl_t<br/>controller manager"]
        Orch["em_orch_ctrl_t<br/>coordinates controller work"]
        Executor["em_cmd_ctrl_t<br/>executes controller commands"]
        Command["em_cmd_t<br/>command and operation context"]

        Ctrl --> Orch --> Executor --> Command
    end

    subgraph Model[In-memory controller data model]
        DataModel["dm_easy_mesh_ctrl_t<br/>central controller model"]
        ModelList["dm_easy_mesh_list_t<br/>managed model instances"]
        Topology["em_network_topo_t<br/>topology view"]
        MLO["AP MLD, backhaul STA MLD,<br/>associated STA MLD, TID-to-link"]

        DataModel --> ModelList
        DataModel --> Topology
        DataModel --> MLO
    end

    subgraph Entities[Controller entity lists]
        Network["Network"]
        Device["Device"]
        SSID["Network SSID"]
        Radio["Radio and radio capability"]
        OpClass["Operating class"]
        BSS["BSS"]
        STA["Station"]
        Policy["Policy"]
        Scan["Scan result"]

        ModelList --> Network & Device & SSID & Radio & OpClass
        ModelList --> BSS & STA & Policy & Scan
    end

    subgraph Persistence[Database adapter and storage]
        Adapter["db_easy_mesh_t<br/>abstract table adapter"]
        Operations["Table operations<br/>create / load / sync / search<br/>insert / update / delete"]
        DBClient["db_client_t<br/>MariaDB C-client wrapper"]
        SQL["SQL statements and result iteration"]
        MariaDB[("MariaDB persistent database")]

        Adapter --> Operations --> DBClient --> SQL --> MariaDB
    end

    subgraph Lifecycle[Persistence lifecycle]
        Init["Controller initialization"]
        Load["load_table()<br/>database → in-memory lists"]
        Change["Configuration or topology change"]
        Save["set_config() / update_db()<br/>in-memory model → database"]

        Init --> Load
        Change --> Save
    end

    TR181["TR-181 adapter"] <--> DataModel
    Orch <--> DataModel
    Command <--> DataModel

    Network & Device & SSID & Radio & OpClass --> Adapter
    BSS & STA & Policy & Scan --> Adapter
    DataModel --> DBClient
    Load --> DBClient
    Save --> Adapter
```

The persisted controller lists are network, device, network SSID, radio,
operating class, BSS, station, policy, and scan result. MLO entities are part
of the in-memory controller model but are not shown as a database-list mapping
in this diagram.

Relevant sources: `src/ctrl/dm_easy_mesh_ctrl.cpp`, `src/dm/`, `src/db/`,
`inc/dm_easy_mesh_ctrl.h`, `inc/db_easy_mesh.h`, and `inc/db_client.h`.

## NO-DB: `no_db.patch` backend-selection design

This diagram represents the proposed changes in `no_db.patch`; it does not
claim that the patch has already been applied. The patch preserves the
controller's in-memory data model and table logic, but replaces its fixed
MariaDB client with a selectable persistence backend.

**Color key:** muted gray = base design being replaced; dashed gray =
transition/refactor point; blue = retained controller or table logic; green =
new entity introduced by the patch; amber = runtime storage target.

This single diagram keeps the overall backend-selection representation while
showing the transition from the base design.

```mermaid
flowchart LR
    subgraph Before[Before: base design]
        OldCtrl["em_ctrl_t"]
        OldModel["dm_easy_mesh_ctrl_t"]
        OldClient["db_client_t<br/>concrete MariaDB wrapper"]
        OldDB[("MariaDB")]
        OldCtrl --> OldModel --> OldClient --> OldDB
    end

    subgraph Transition[Gray refactor transition]
        T1["db_client_t becomes<br/>an abstract interface"]
        T2["m_db_client changes<br/>value → owned pointer"]
        T3["Call sites change<br/>m_db_client → *m_db_client"]
    end

    subgraph After[After: no_db.patch backend-selection design]
        Ctrl["em_ctrl_t<br/>retained startup logic"]
        DataModel["dm_easy_mesh_ctrl_t<br/>retained in-memory model"]
        Lists["dm_*_list_t<br/>retained entity containers"]
        TableAdapter["db_easy_mesh_t<br/>retained table and row logic"]
        Env["EM_DB_TYPE<br/>local (default) / none / cloud"]
        Type["db_client_type_t"]
        Factory["db_client_factory_t<br/>type_from_string() + create()"]
        Client["db_client_t<br/>abstract interface"]
        Methods["init, execute, next_result,<br/>get_string, get_number, recreate_db"]
        Local["db_client_local_t<br/>on-box MariaDB behavior"]
        None["db_client_none_t<br/>no-op backend"]
        Cloud["db_client_cloud_t<br/>future stub"]
        MariaDB[("MariaDB / MySQL")]
        Memory["Controller memory only<br/>no reads or writes"]

        Ctrl --> DataModel --> Lists --> TableAdapter
        Ctrl --> Env --> Factory
        Type --> Factory --> Client --> Methods
        DataModel -->|owns db_client_t pointer| Client
        TableAdapter -->|uses db_client_t reference| Client
        Client --> Local --> MariaDB
        Client --> None --> Memory
        Client --> Cloud
    end

    OldClient -. replaced .-> T1 -.-> Client
    OldModel -. ownership .-> T2 -.-> DataModel
    OldClient -. call usage .-> T3 -.-> TableAdapter

    classDef old fill:#f3f4f6,stroke:#9ca3af,color:#6b7280,stroke-width:2px;
    classDef transition fill:#e5e7eb,stroke:#6b7280,color:#374151,stroke-width:2px,stroke-dasharray: 5 5;
    classDef retained fill:#dbeafe,stroke:#2563eb,color:#111827,stroke-width:2px;
    classDef introduced fill:#dcfce7,stroke:#16a34a,color:#111827,stroke-width:2px;
    classDef storage fill:#fef3c7,stroke:#d97706,color:#111827,stroke-width:2px;

    class OldCtrl,OldModel,OldClient,OldDB old;
    class T1,T2,T3 transition;
    class Ctrl,DataModel,Lists,TableAdapter retained;
    class Env,Type,Factory,Client,Methods,Local,None,Cloud introduced;
    class MariaDB,Memory storage;
```

With `EM_DB_TYPE=none`, the factory returns `db_client_none_t`. Database calls
remain valid calls through `db_client_t`, but the backend returns no rows and
performs no writes. The existing `dm_*_list_t` containers therefore remain the
authoritative runtime state. `local` remains the default and retains the
MariaDB-backed behavior; `cloud` is wired through the factory but deliberately
fails until implemented.

Patch-specific files: `no_db.patch`, `inc/db_client*.h`,
`src/db/db_client_{local,none,cloud,factory}.cpp`,
`inc/dm_easy_mesh_ctrl.h`, and `src/ctrl/{dm_easy_mesh_ctrl,em_ctrl}.cpp`.
