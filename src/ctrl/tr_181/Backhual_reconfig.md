# Backhaul SSID Reconfiguration Flow

This document describes the current controller and agent flow for backhaul SSID/passphrase reconfiguration.

![Reference figure for WSC Backhaul STA reconfiguration](Backhaul_reconfig.png)

## Current Behavior

1. Backhaul SetSSID request enters `em_ctrl_t::cmd_setssid()`.
2. Controller enables a transaction lock (`m_backhaul_reconfig_in_progress`) to block onboarding of unknown agents during the run.
3. Controller runs recursive post-order orchestration through `em_ctrl_t::backhaul_reconfig(...)`.
4. Each visited agent uses the same exchange path via `send_backhaul_reconfig_exchange(...)`.
5. For each target agent, controller dispatches `cfg_renew` on all radios, waits for M1->M2 completion signal, and retries up to `MAX_EXCHANGE_RETRIES`.
6. Co-located agent is processed in the same recursive traversal (post-order), not by a separate final apply stage.
7. Flow success/failure is based on bounded exchange completion only. There is no runtime post-exchange verification poll stage.
8. Transaction lock is released before returning success/failure.

## Constants In Use

1. `MAX_EXCHANGE_RETRIES = 3`
2. `MAX_COLOCATED_APPLY_RETRIES = 3` (kept for compatibility helper API)
3. `EXCHANGE_COMPLETE_TIMEOUT = 15s`
4. `M1_TIMEOUT = 5s` (reserved)

## Capability Handling

1. AP Capability TLV advertises `m8_bsta_reconfiguration = 1`.
2. Capability report parsing stores this into `radio_info.support_m8_bsta_reconfiguration`.
3. M2 construction appends M8 for backhaul only when the stored capability is true.

## Onboarding Guard

1. While `m_backhaul_reconfig_in_progress` is true, unknown AL-MAC onboarding via autoconfig search is rejected.
2. Existing known agents in the topology continue in the reconfiguration flow.


## Topology Shapes (Reference Only)

The topology diagrams below are shape references only. A single unified recursive post-order flow is used for all of them.

**Pure Star** — all agents are directly connected to the controller (depth=1 each):

```mermaid
flowchart LR
    CTRL[Controller] --- CA[Co-located Agent]
    CA --> S1[Star Agent 1 - depth 1]
    CA --> S2[Star Agent 2 - depth 1]
    CA --> S3[Star Agent 3 - depth 1]
```

**Daisy Chain** — agents form a linear chain with increasing depth:

```mermaid
flowchart LR
    CTRL[Controller] --- CA[Co-located Agent]
    CA --> D1[Daisy Agent L1 - depth 1] --> D2[Daisy Agent L2 - depth 2] --> D3[Daisy Agent L3 - nth leaf - depth n]
```

**Mixed** — combination of star and daisy-chain agents:

```mermaid
flowchart LR
    CTRL[Controller] --- CA[Co-located Agent]
    CA --> S1[Star Agent 1 - depth 1]
    CA --> S2[Star Agent 2 - depth 1]
    CA --> D1[Daisy Agent L1 - depth 1] --> D2[Daisy Agent L2 - depth 2] --> D3[Daisy Agent L3 - nth leaf - depth n]
```

## Recursive Post-Order Flow

```mermaid
flowchart TD
    A[Backhaul SetSSID or PassPhrase received by Controller] --> B[Controller stores new credentials in temp variables and calls backhaul_reconfig on topology root node]
    B --> C{Node is a leaf?<br/>OR all child backhaul_reconfig calls returned SUCCESS?}
    C -->|Yes| D[send cfg_renew to all radios of this node and wait for m1, m2+m8 exchange to complete]
    C -->|No| E[Call backhaul_reconfig on all child nodes]
    E -->|Loop to decision| C
```

## Agent Reconfiguration Flow
```mermaid
flowchart TD
    A[Agent receives AP-Autoconfig Renew from Controller] --> B[handle_autoconfig_renew - Agent sends M1 to Controller]
    B --> C[Agent receives M2 plus M8 from Controller - handle_autoconfig_wsc_m2]
    C --> D[Decrypt and parse each WSC TLV - extract SSID passphrase haul_type per BSS]
    D --> E[If M8 TLV present: extract backhaul SSID and passphrase from M8, otherwise proceed with M2 credentials only]
    E --> H[Build m2ctrl_radioconfig with all BSS entries including backhaul haul type]
    H --> I[Dispatch em_bus_event_type_m2ctrl_configuration to agent - io_process]
    I --> J[analyze_m2ctrl_configuration - copy SSID passphrase haul_type for each BSS]
    J --> K[refresh_onewifi_subdoc - encode updated config via webconfig_easymesh_encode]
    K --> L[Push encoded subdoc to OneWifi via WIFI_WEBCONFIG_DOC_DATA_SOUTH bus set]
    L --> M[OneWifi persists backhaul credentials in /nvram/EasymeshCfg.json]
    M --> N[Update keys: Backhaul_SSID=<new backhaul SSID> and Backhaul_KeyPassphrase=<new backhaul passphrase>]
    N --> O[OneWifi applies new BSS credentials - state = em_state_agent_owconfig_pending]
    O --> P[bSTA disconnects from old backhaul SSID and reconnects using new SSID and passphrase]
    P --> Q[state = em_state_agent_onewifi_bssconfig_ind - agent reconnected to parent backhaul BSS]
    Q --> R[Controller verifies reconnection via topology and link-status polling]
```
Agent Reconfiguration Flow
## Sequence Summary

```mermaid
sequenceDiagram
    participant CTRL as Controller
    participant A as Agent Node (post-order)

    CTRL->>CTRL: set_backhaul_reconfig_in_progress(true)
    CTRL->>CTRL: backhaul_reconfig(root)
    CTRL->>A: cfg_renew (all radios)
    A-->>CTRL: M1
    CTRL->>A: M2 (+M8 when capability=true)
    CTRL->>CTRL: mark exchange complete via M2 TX event
    CTRL->>CTRL: retry/timeout handling per agent
    CTRL->>CTRL: set_backhaul_reconfig_in_progress(false)
```
## Unified Example and Sequence

Combined topology example: `C -> {S1, S2, A1}` and `A1 -> A2 -> A3`.

Recursive post-order execution trace (actual code behavior):

- `cmd_setssid(backhaul)` sets `m_backhaul_reconfig_in_progress=true` and invokes `backhaul_reconfig(g_network_topology, &ctx)`.
- `backhaul_reconfig(...)` uses post-order traversal and calls `send_backhaul_reconfig_exchange(...)` for each visited node.
- For `S1` and `S2` (leaves), controller sends `cfg_renew` on all radios, waits for exchange completion, and retries (bounded) if needed.
- For branch `A1 -> A2 -> A3`, post-order visits `A3`, then `A2`, then `A1`, each through the same exchange function.
- Exchange completion is marked by M2 TX event handling (`handle_m2_tx -> mark_backhaul_exchange_complete_by_al`) for the active agent window.
- Co-located/controller node is not handled by a separate final apply stage; it is part of the same traversal path.
- If a node has no bSTA, `send_backhaul_reconfig_exchange(...)` returns success for that node without running exchange.
- On first exchange failure after retries, traversal fails fast and `cmd_setssid` returns failure.
- On overall success, `cmd_setssid` returns success and clears the transaction lock.
- There is no runtime post-exchange verification polling gate in this path.

```mermaid
sequenceDiagram
    participant CTRL as Controller
    participant CA as Co-located Agent
    participant S1 as Star Agent S1
    participant S2 as Star Agent S2
    participant A1 as Daisy Agent A1
    participant A2 as Daisy Agent A2
    participant A3 as Daisy Agent A3 (leaf)

    Note over CTRL: Backhaul SSID/passphrase change received
    CTRL->>CTRL: set_backhaul_reconfig_in_progress(true)
    Note over CTRL: backhaul_reconfig(root) using post-order traversal
    CTRL->>S1: cfg_renew on all radios of S1
    S1-->>CTRL: M1
    CTRL->>S1: M2+M8
    CTRL->>CTRL: M2 TX event marks S1 exchange complete
    CTRL->>S2: cfg_renew on all radios of S2
    S2-->>CTRL: M1
    CTRL->>S2: M2+M8
    CTRL->>CTRL: M2 TX event marks S2 exchange complete
    Note over CTRL: Recurse into A1 branch - leaf A3 first
    CTRL->>A3: cfg_renew on all radios of A3
    A3-->>CTRL: M1
    CTRL->>A3: M2+M8
    CTRL->>CTRL: M2 TX event marks A3 exchange complete
    Note over CTRL: A3 done - send to A2
    CTRL->>A2: cfg_renew on all radios of A2
    A2-->>CTRL: M1
    CTRL->>A2: M2+M8
    CTRL->>CTRL: M2 TX event marks A2 exchange complete
    Note over CTRL: A2 done - send to A1
    CTRL->>A1: cfg_renew on all radios of A1
    A1-->>CTRL: M1
    CTRL->>A1: M2+M8
    CTRL->>CTRL: M2 TX event marks A1 exchange complete
    Note over CTRL,CA: CA handled in same traversal path (or skipped if no bSTA)
    CTRL->>CTRL: set_backhaul_reconfig_in_progress(false)
    CTRL-->>CTRL: return Success or Failure
```

## Need To Work

1. What if one agent updated to the new credential and another agent did not?
    Current behavior: flow is fail-fast in a unified exchange path, but partial remote updates can still occur before a later agent fails. Those partially updated agents may disconnect and require recovery/re-onboarding.
    Need to work: add explicit partial-update handling with a recovery policy (automatic rollback where possible, otherwise targeted re-onboard workflow) and publish an alarm containing the impacted agent list.

2. What if a new agent is onboarded during reconfiguration?
    Current behavior: onboarding during an active reconfiguration window is not transaction-isolated, so timing can cause old/new credential race conditions.
    Need to work: introduce a reconfiguration epoch/lock, queue or gate onboarding until exchange orchestration completes, then run a reconciliation pass to force consistent backhaul credentials on newly onboarded agents.

## Notes

1. Documentation and code intentionally do not include a runtime post-exchange polling gate anymore.
2. Operational convergence is expected from normal topology/data-model updates after successful exchanges.

## Detailed Code Flow (Actual Implementation)

```mermaid
sequenceDiagram
    participant API as API Layer
    participant CMD as cmd_setssid()
    participant LOCK as Transaction Lock
    participant BH as backhaul_reconfig()
    participant EX as send_backhaul_reconfig_exchange()
    participant IO as io_process()
    participant Event as M2 TX Event Handler

    API->>CMD: SetSSID request with HaulType="backhaul"
    CMD->>CMD: Check HaulType == "backhaul"
    CMD->>LOCK: set_backhaul_reconfig_in_progress(true)
    LOCK->>LOCK: m_backhaul_reconfig_in_progress = true
    CMD->>CMD: Create em_backhaul_reconfig_context_t
    CMD->>CMD: Store payload in reconfig_ctx
    CMD->>BH: backhaul_reconfig(g_network_topology, &ctx)
    
    BH->>BH: Reset pending_exchange map
    BH->>BH: flow_start_time = time(NULL)
    BH->>BH: traverse_post_order(callback)
    
    Note over BH: For each node leaf-first (post-order):
    BH->>EX: send_backhaul_reconfig_exchange(agent_dm, ctx)
    
    EX->>EX: Check if agent has bSTA
    rect rgba(0, 255, 0, 0.1)
        Note over EX: Agent has bSTA - proceed
        EX->>EX: pending_exchange[agent] = false
        EX->>EX: m_active_backhaul_agent = agent_dm
        
        loop Retry loop (MAX_EXCHANGE_RETRIES=3)
            EX->>EX: For each radio of agent
            EX->>IO: io_process(cfg_renew)
            IO->>IO: Dispatch cfg_renew event
            
            EX->>EX: m_backhaul_exchange_window_open = true
            EX->>EX: exchange_start = time(NULL)
            
            loop Wait up to 15s (EXCHANGE_COMPLETE_TIMEOUT)
                Event->>EX: M2 TX event triggers
                Event->>Event: mark_backhaul_exchange_complete_by_al()
                Event->>EX: pending_exchange[agent] = true
            end
            
            alt Exchange completed
                EX->>EX: exchange_complete = true
                EX->>EX: m_active_backhaul_agent = NULL
                EX->>EX: Return SUCCESS
            else Timeout (not completed)
                EX->>EX: Back off 5 seconds
                EX->>EX: Continue to next retry
            end
        end
    end
    
    rect rgba(255, 0, 0, 0.1)
        Note over EX: Agent has no bSTA - skip
        EX->>EX: Return SUCCESS (no exchange needed)
    end
    
    Note over BH: All nodes completed in post-order
    BH->>BH: m_active_backhaul_ctx = prev_ctx
    BH->>BH: Return SUCCESS or FAIL
    
    CMD->>LOCK: set_backhaul_reconfig_in_progress(false)
    LOCK->>LOCK: m_backhaul_reconfig_in_progress = false
    CMD->>API: Return Success or Failure status
```

**Code Flow Reference Points:**

| Function | File | Purpose |
|----------|------|---------|
| `cmd_setssid()` | `dm_easy_mesh_ctrl.cpp:64` | Entry point, checks HaulType, sets transaction lock |
| `backhaul_reconfig()` | `em_ctrl.cpp:1284` | Recursive post-order traversal orchestrator |
| `send_backhaul_reconfig_exchange()` | `em_ctrl.cpp:1342` | Per-agent cfg_renew → M1 → M2+M8 exchange with retries |
| `mark_backhaul_exchange_complete_by_al()` | `em_ctrl.cpp:246` | M2 TX event callback, marks exchange complete |
| `io_process(em_bus_event_type_cfg_renew, ...)` | Event dispatch | Sends cfg_renew to agent |