# Backhaul SSID Reconfiguration — Change Log

## Summary

Implementation of EasyMesh Section 5.2.5 (WSC Reconfiguration of Backhaul STA).
Adds multi-phase leaf-first backhaul SSID reconfiguration across the mesh topology
tree, with M8 bSTA Reconfiguration capability validation.

---

## Files Modified

### 1. `inc/em_base.h`

**Changes:**
- **`em_ap_capability_t` struct** (~line 1907): Pre-existing bit field
  `m8_bsta_reconfiguration:1` — no change, used as-is for TLV encoding/decoding.
- **`em_device_info_t` struct** (~line 2275): Added `bool m8_bsta_reconfiguration`
  field to store the AP Capability TLV bit at the device level. Placed after the
  `sec_1905` field.

**Why:** The TLV bit field (`em_ap_capability_t`) is packed for wire format. A
separate `bool` in `em_device_info_t` provides convenient device-level access for
the controller's validation loop.

---

### 2. `inc/em_network_topo.h`

**Changes:**
- Added private member `bool m_bh_processed` — per-node flag tracking whether this
  node's radios have been submitted as candidates during the current reconfig cycle.
- Added private member `bool m_bh_reconfig_active` — root-only flag indicating a
  multi-phase backhaul reconfig is in progress.
- Added forward declarations for `em_orch_t` and `em_cmd_t`.
- Added public methods:
  - `int backhaul_reconfig(hash_map_t *em_map, em_cmd_t *pcmd)` — builds candidates
    for the next unprocessed leaf layer.
  - `bool is_bh_reconfig_complete()` — checks if root node is processed.
  - `bool is_bh_reconfig_active()` — inline getter for the active flag.
  - `void set_bh_reconfig_active(bool active)` — inline setter.
  - `void send_bh_reconfig_event()` — sends internal bus event for next phase.
  - `void reset_bh_reconfig()` — recursively resets all `m_bh_processed` flags.

---

### 3. `src/ctrl/em_network_topo.cpp`

**Changes:**
- **Removed includes:** `em_cmd_set_bh_cfg.h`, `em_orch.h` (unused after refactor).
- **Added `backhaul_reconfig()`:** Recursive post-order traversal. Skips processed
  nodes, recurses into children, then adds this node's radios as candidates when
  all children are done. Returns count of radios added.
- **Added `is_bh_reconfig_complete()`:** Returns `m_bh_processed` on root node.
- **Added `reset_bh_reconfig()`:** Recursively sets `m_bh_processed = false` on
  all nodes.
- **Added `send_bh_reconfig_event()`:** Creates `em_event_t` with
  `em_bus_event_type_set_bh_cfg` and sends via `cmd_ctrl->send_cmd()`.
- **Updated constructors:** Both `em_network_topo_t()` and
  `em_network_topo_t(dm_easy_mesh_t*)` initialize `m_bh_processed = false` and
  `m_bh_reconfig_active = false`.

---

### 4. `src/ctrl/em_ctrl.cpp`

**Changes:**
- **Added include:** `em_network_topo.h`.
- **Added `handle_set_bh_cfg()`:** New handler for `em_bus_event_type_set_bh_cfg`.
  Two execution paths:
  1. **Initial path** (from `io_process`): Calls `analyze_set_bh_cfg()` to validate
     the backhaul SSID change. Iterates all agent data models checking
     `m8_bsta_reconfiguration`. Resets topology flags and submits command with the
     analyzed DM (which carries the DB update).
  2. **Re-trigger path** (from `send_bh_reconfig_event()`): Detected via
     `is_bh_reconfig_active()`. Submits command with global `m_data_model`. Handles
     empty-layer case by re-triggering or deactivating.
- **Added `em_bus_event_type_set_bh_cfg` case** in `handle_bus_event()` switch.

---

### 5. `src/orch/em_orch_ctrl.cpp`

**Changes:**
- **Added includes:** `em_network_topo.h`.
- **Added extern:** `em_network_topo_t *g_network_topology`.
- **`build_candidates()` — `em_cmd_type_set_bh_cfg` case:** Calls
  `g_network_topology->backhaul_reconfig(m_mgr->m_em_map, pcmd)`. Performs
  `pthread_mutex_unlock(&m_mgr->m_mutex)` before early return (since the function
  holds the mutex at entry).
- **`is_em_ready_for_orch_fini()` — `em_cmd_type_set_bh_cfg` case:** Separate from
  `set_ssid`. Waits for `em_state_ctrl_configured` (not `em_state_ctrl_wsc_m2_sent`)
  to ensure agents have fully applied the new backhaul config. Includes
  `EM_MAX_RENEW_TX_THRESH` safety valve.
- **`is_em_ready_for_orch_exec()` — `em_cmd_type_set_bh_cfg` case:** Added alongside
  `set_ssid`, always returns true (execute immediately).

---

### 6. `src/orch/em_orch.cpp`

**Changes:**
- **Added includes:** `em_network_topo.h`.
- **Added extern:** `em_network_topo_t *g_network_topology`.
- **`handle_timeout()` — post-fini hook for `set_bh_cfg`:** After detecting fini
  (all candidates in layer done):
  - Checks `is_bh_reconfig_complete()`.
  - If not complete: sets `bh_reconfig_next = true`.
  - If complete: calls `set_bh_reconfig_active(false)` and `reset_bh_reconfig()`.
  - After `destroy_command()`: if `bh_reconfig_next`, calls
    `send_bh_reconfig_event()` to trigger the next topology layer.

---

### 7. `src/em/em.cpp`

**Changes:**
- **`create_ap_cap_tlv()`** (~line 1005): Added
  `ap_cap->m8_bsta_reconfiguration = 1` to advertise that the agent supports WSC
  reconfiguration of the backhaul STA.

---

### 8. `src/em/capability/em_capability.cpp`

**Changes:**
- **`handle_ap_cap_report()`** (~line 1162): Added storage of the M8 bit from the
  received AP Capability TLV into the device-level data model:
  ```cpp
  dm->m_device.m_device_info.m8_bsta_reconfiguration =
      ap_cap->m8_bsta_reconfiguration ? true : false;
  ```

---

### 9. `inc/em_cmd_set_bh_cfg.h`

**Changes:**
- **Removed:** Unused per-device constructor declaration
  (`em_cmd_set_bh_cfg_t(em_cmd_params_t, dm_easy_mesh_t&, dm_easy_mesh_t&)`).
- **Added:** Doxygen comment block for the remaining single constructor.
- Class now has a single constructor: `em_cmd_set_bh_cfg_t(em_cmd_params_t, dm_easy_mesh_t&)`.

---

### 10. `src/cmd/em_cmd_set_bh_cfg.cpp`

**Changes:**
- **Removed:** Unused per-device constructor implementation.
- **Fixed:** Double-semicolon on `ctx` variable declaration.
- Single constructor configures two orch descriptors:
  `dm_orch_type_db_cfg` (submit=true) + `dm_orch_type_net_ssid_update`.

---

## New Files

| File | Purpose |
|------|---------|
| `docs/backhaul-ssid-reconfig-design.md` | Design document with architecture, flow diagrams, and component details |
| `docs/backhaul-ssid-reconfig-changelog.md` | This file — per-file change log |
