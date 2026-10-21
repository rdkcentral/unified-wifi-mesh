
#include <stdbool.h>
#include <sys/time.h>
#include <stdint.h>  /* Defines uint8_t, uint16_t, uint32_t, etc. */
#include <stddef.h>  /* Defines size_t */
#include "wifi_base.h"

/* OneWifi publishes local link-quality stats here; the EM agent listener binds it. */
#define LQ_STATS_SOCKET_PATH "/tmp/linkquality_stats.sock"
/* EM controller forwards aggregated stats here; the WEI app binds it (fed only via controller). */
#define LQ_STATS_EM_SOCKET_PATH "/tmp/linkquality_stats_em.sock"

#define LQ_IPC_MSG_PERIODIC_STATS    1
#define LQ_IPC_MSG_DISCONNECT        2
#define LQ_IPC_MSG_RAPID_DISCONNECT  3
#define LQ_IPC_MSG_CAFFINITY_EVENT   4
#define LQ_IPC_MSG_START_METRICS     5
#define LQ_IPC_MSG_STOP_METRICS      6
#define LQ_IPC_MSG_REGISTER_STA      7
#define LQ_IPC_MSG_UNREGISTER_STA    8
#define LQ_IPC_MSG_REINIT_METRICS    9
#define LQ_IPC_MSG_SET_MAX_SNR      10
#define LQ_IPC_MSG_SET_SCORE_PARAMS 11

typedef char mac_addr_str_t[18]; /**< MAC address string type. */

/*
 * LQ TLV — the entire datagram is a single TLV, no wrapper header.
 *
 *   type  – LQ_IPC_MSG_* (1–10); uint8_t is sufficient
 *   len   – payload byte count; uint16_t covers all realistic payloads
 *   value – raw payload bytes (stats_arg_t[], server_arg_t, MAC string, etc.)
 *
 * Total header: 3 bytes (packed). AF_UNIX SOCK_DGRAM preserves exact datagram
 * boundaries. The receiver derives element count from len / sizeof(element_type).
 */
typedef struct {
    uint8_t  type;
    uint16_t len;
    uint8_t  value[];
} __attribute__((__packed__)) lq_tlv_t;

int lq_ipc_send_wei_data(uint32_t msg_type, const stats_arg_t *entries, uint32_t count);

/* Shared by lq_socket.cpp (sender) and lq_listener.cpp (receiver) for logging. */
static inline const char *lq_msg_type_str(uint32_t type)
{
    switch (type) {
    case LQ_IPC_MSG_PERIODIC_STATS:   return "PERIODIC_STATS";
    case LQ_IPC_MSG_DISCONNECT:       return "DISCONNECT";
    case LQ_IPC_MSG_RAPID_DISCONNECT: return "RAPID_DISCONNECT";
    case LQ_IPC_MSG_CAFFINITY_EVENT:  return "CAFFINITY_EVENT";
    case LQ_IPC_MSG_START_METRICS:    return "START_METRICS";
    case LQ_IPC_MSG_STOP_METRICS:     return "STOP_METRICS";
    case LQ_IPC_MSG_REGISTER_STA:     return "REGISTER_STA";
    case LQ_IPC_MSG_UNREGISTER_STA:   return "UNREGISTER_STA";
    case LQ_IPC_MSG_REINIT_METRICS:   return "REINIT_METRICS";
    case LQ_IPC_MSG_SET_MAX_SNR:      return "SET_MAX_SNR";
    case LQ_IPC_MSG_SET_SCORE_PARAMS: return "SET_SCORE_PARAMS";
    default:                          return "UNKNOWN";
    }
}
