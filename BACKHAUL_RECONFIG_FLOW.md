# Backhaul Reconfiguration Flow

```
START: backhaul_reconfig(root_topo, context)
  ├─ Validate inputs
  ├─ Initialize context (if controller)
  └─ Post-order traverse:
       ├─ AgentA1.process_backhaul_agent()
       │  └─ send_backhaul_reconfig_exchange()
       │     ├─ Dispatch cfg_renew → M1
       │     ├─ Wait 15s for M2+M8 (with retries)
       │     └─ Return SUCCESS/FAIL
       ├─ AgentA2.process_backhaul_agent() [same]
       ├─ AgentA.process_backhaul_agent() [same]
       └─ ... (all agents in post-order)
  ├─ Controller (parent last)
  └─ RETURN traversal result
```
