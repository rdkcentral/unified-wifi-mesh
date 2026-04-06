# Backhaul SSID Reconfiguration — Design Document

## 1. Overview

This document describes the implementation of **Backhaul SSID Reconfiguration** per
EasyMesh Section 5.2.5 (WSC Reconfiguration of Backhaul STA). The feature allows
the controller to change the backhaul SSID/passphrase on all agents in a mesh
network, reconfiguring them in a **leaf-first post-order traversal** so that child
agents are reconfigured before their parents, avoiding network splits.

### 1.1 Key Requirements

1. **M8 bSTA Reconfiguration capability check** — Before initiating reconfig, the
   controller verifies that every agent advertises `M8_bSTA_Reconfiguration = 1`
   in the AP Capability TLV (Type 0xA1).
2. **Leaf-first (post-order) reconfiguration** — Leaf agents are reconfigured first,
   then their parents, up to the co-located agent (root). This prevents parent
   agents from losing connectivity to children mid-reconfig.
3. **Multi-phase orchestration** — Each layer of the topology tree is submitted as a
   separate orchestrator command. After all radios in a layer reach the
   `em_state_ctrl_configured` state, a bus event triggers the next layer.

---

## 2. Architecture & Flow

### 2.1 High-Level Flow

```
  CLI / NB API
       |
       v
  cmd_setssid (backhaul change detected)
       |
       v
  io_process(em_bus_event_type_set_bh_cfg)
       |
       v
  handle_set_bh_cfg()      [em_ctrl.cpp]
       |
       |--- (1) analyze_set_bh_cfg() → validate JSON, diff SSID config
       |--- (2) M8 bSTA Reconfiguration check (all agents)
       |--- (3) reset_bh_reconfig() + set_bh_reconfig_active(true)
       |--- (4) submit_command(em_cmd_set_bh_cfg_t)
       |                |
       |                v
       |         build_candidates()  [em_orch_ctrl.cpp]
       |                |
       |                v
       |         backhaul_reconfig()  [em_network_topo.cpp]
       |           (pushes leaf-layer radios as candidates)
       |                |
       |                v
       |         Orchestrator: pending → active → execute
       |           (autoconfig renew → M1/M2 → topo sync → configured)
       |                |
       |                v
       |         is_em_ready_for_orch_fini()
       |           waits for em_state_ctrl_configured
       |                |
       |                v
       |         handle_timeout() detects fini  [em_orch.cpp]
       |                |
       |                +--- is_bh_reconfig_complete()?
       |                |       |
       |                |    NO: set bh_reconfig_next = true
       |                |   YES: set_bh_reconfig_active(false)
       |                |         reset_bh_reconfig()
       |                |
       |                v
       |         destroy_command()
       |                |
       |         if bh_reconfig_next:
       |                v
       |         send_bh_reconfig_event()  ──┐
       |                                     |
       └────── handle_set_bh_cfg() ◄─────────┘
                 (re-trigger path: is_bh_reconfig_active() == true)
                        |
                        v
                 submit_command() → build_candidates() → backhaul_reconfig()
                   (next leaf layer's radios become candidates)
                        |
                        v
                 ... cycle repeats until root is processed ...
```

### 2.2 Post-Order Topology Traversal

The topology tree (`em_network_topo_t`) mirrors the mesh backhaul hierarchy:

```
        Controller (root / co-located agent)
            /               \
       Agent A             Agent B
        /                   /    \
   Agent C              Agent D   Agent E
```

**Phase 1:** Agents C, D, E (leaves) — all have zero children, so they qualify
immediately. Their radios are pushed as candidates and `m_bh_processed = true`.

**Phase 2:** Agents A, B — all children are now processed, so these nodes qualify.

**Phase 3:** Controller (root) — all children processed, root qualifies.

The `backhaul_reconfig()` function implements this by:
1. Skipping already-processed nodes (`m_bh_processed == true`)
2. Recursing into children first
3. Only adding a node's radios as candidates when **all** children are processed
4. Marking the node as processed after adding its radios

---

## 3. Component Details

### 3.1 M8 bSTA Reconfiguration Capability

**EasyMesh Reference:** Section 17.2.6 — AP Capability TLV (Type 0xA1)

```
Bit 3: M8_bSTA_Reconfiguration
  0 = Agent does not support WSC reconfiguration of backhaul STA
  1 = Agent supports WSC reconfiguration of backhaul STA
```

#### Agent Side (em.cpp — `create_ap_cap_tlv`)
The agent advertises support by setting the bit to 1 when building the AP
Capability TLV in AP Capability Report messages:

```cpp
ap_cap->m8_bsta_reconfiguration = 1;
```

#### Controller Side — Storage (em_capability.cpp — `handle_ap_cap_report`)
When the controller receives an AP Capability Report, it stores the bit in the
device-level data model:

```cpp
dm->m_device.m_device_info.m8_bsta_reconfiguration =
    ap_cap->m8_bsta_reconfiguration ? true : false;
```

#### Controller Side — Validation (em_ctrl.cpp — `handle_set_bh_cfg`)
Before starting reconfig, the controller iterates over all agent data models and
aborts if any agent does not support the capability:

```cpp
dm_easy_mesh_t *agent_dm = m_data_model.get_first_dm();
while (agent_dm != NULL) {
    if (agent_dm->is_controller() == false &&
        agent_dm->m_device.m_device_info.m8_bsta_reconfiguration == false) {
        // Abort — agent does not support bSTA reconfiguration
        return;
    }
    agent_dm = m_data_model.get_next_dm(agent_dm);
}
```

### 3.2 handle_set_bh_cfg — Two Execution Paths

`handle_set_bh_cfg()` in `em_ctrl.cpp` handles the `em_bus_event_type_set_bh_cfg`
bus event. It operates in two distinct modes:

| Path | Trigger | Actions |
|------|---------|---------|
| **Initial** | `io_process` from CLI/NB API | Validate config, check M8 bit, reset topology flags, submit command with analyzed DM |
| **Re-trigger** | `send_bh_reconfig_event()` after a layer completes | Skip validation, submit command with global `m_data_model` for next layer |

The `is_bh_reconfig_active()` flag on the root topology node distinguishes the
two paths.

### 3.3 Orchestrator Fini Condition

For `em_cmd_type_set_bh_cfg`, the fini condition in `is_em_ready_for_orch_fini()`
waits for **`em_state_ctrl_configured`** (not `em_state_ctrl_wsc_m2_sent` as used
by `set_ssid`). This ensures that agents have fully applied the new backhaul
configuration before the next layer is triggered.

```cpp
case em_cmd_type_set_bh_cfg:
    if (em->get_state() == em_state_ctrl_configured) {
        return true;
    }
    break;
```

### 3.4 Bus Event Re-trigger (Post-Fini Hook)

In `em_orch.cpp`'s `handle_timeout()`, after a `set_bh_cfg` command reaches fini:

1. Check `is_bh_reconfig_complete()` (root node processed?)
2. If **not complete**: set `bh_reconfig_next = true`
3. If **complete**: deactivate and reset all flags
4. After `destroy_command()`, if `bh_reconfig_next`: call `send_bh_reconfig_event()`

`send_bh_reconfig_event()` creates an `em_event_t` with
`em_bus_event_type_set_bh_cfg` and sends it via `cmd_ctrl->send_cmd()`, which
re-enters `handle_set_bh_cfg()` through the re-trigger path.

### 3.5 em_cmd_set_bh_cfg_t Command

The command has a single constructor taking `(em_cmd_params_t, dm_easy_mesh_t&)`.
It configures two orchestrator descriptors:

| Index | Orch Type | Purpose |
|-------|-----------|---------|
| 0 | `dm_orch_type_db_cfg` | Commits SSID config to database (submit = true) |
| 1 | `dm_orch_type_net_ssid_update` | Loads updated network SSID table |

---

## 4. Data Structures

### 4.1 em_network_topo_t — Per-Node Fields

| Field | Type | Scope | Description |
|-------|------|-------|-------------|
| `m_bh_processed` | `bool` | Per-node | Whether this node's radios have been submitted as candidates during the current reconfig cycle |
| `m_bh_reconfig_active` | `bool` | Root-only | Whether a multi-phase backhaul reconfig is in progress |

### 4.2 em_device_info_t — Capability Field

| Field | Type | Description |
|-------|------|-------------|
| `m8_bsta_reconfiguration` | `bool` | Stored from AP Capability TLV. True if agent supports WSC reconfiguration of backhaul STA |

### 4.3 em_ap_capability_t — TLV Bit Field

| Field | Type | Description |
|-------|------|-------------|
| `m8_bsta_reconfiguration` | `unsigned char :1` | Bit 3 of AP Capability TLV (Type 0xA1) |

---

## 5. State Machine Per Layer

Each layer of the topology processed by `set_bh_cfg` goes through the standard
orchestrator state machine:

```
  [pending] ──────────> [active]
                           |
                     orch_execute()
                    (set em to misconfigured,
                     send autoconfig renew)
                           |
                           v
                    M1 received from agent
                           |
                           v
                    M2 sent (new backhaul config)
                           |
                           v
                    Topology sync
                           |
                           v
                  em_state_ctrl_configured  ← fini condition
                           |
                           v
                       [fini]
                           |
                    handle_timeout()
                           |
                     ┌─────┴──────┐
                     |            |
               more layers?   all done
                     |            |
              send_bh_reconfig    reset flags
               _event()
```

---

## 6. Edge Cases

| Scenario | Handling |
|----------|----------|
| Agent doesn't support M8 | Rejected at validation; `em_cmd_out_status_not_ready` returned |
| NULL data_model node in topology | Node is marked processed, skipped; re-trigger sent for next layer |
| Command already in progress | `is_cmd_type_in_progress()` returns true; `em_cmd_out_status_prev_cmd_in_progress` returned |
| Renew threshold exceeded | `EM_MAX_RENEW_TX_THRESH` safety valve transitions to fini |
| Topology change during reconfig | Current cycle completes with stale tree; next event will use updated topology |
