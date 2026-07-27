
#include <stdbool.h>
#include <sys/time.h>
#include <stdint.h>  /* Defines uint8_t, uint16_t, uint32_t, etc. */
#include <stddef.h>  /* Defines size_t */


#define LQ_STATS_SOCKET_PATH "/tmp/linkquality_stats.sock"

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
typedef struct {
    unsigned long cli_PacketsSent;
    unsigned long cli_PacketsReceived;
    unsigned long cli_RetransCount;
    unsigned long long cli_RxRetries;
    int cli_SNR;
    unsigned int   cli_MaxDownlinkRate;
    unsigned int cli_MaxUplinkRate;
    unsigned int cli_LastDataDownlinkRate;
    unsigned int cli_LastDataUplinkRate;
    bool cli_PowerSaveMode;
} dev_stats_t;


typedef struct {
    mac_addr_str_t mac_str;
    mac_addr_str_t ap_mac_str;
    unsigned int vap_index;
    unsigned int radio_index;
    int channel_utilization;
    dev_stats_t dev;
    struct timespec total_connected_time;
    struct timespec total_disconnected_time;
    int event;
    unsigned int status_code;
    int dhcp_event;
    int dhcp_msg_type;
    char dhcp_hostname[256];
    char dhcp_vendor_class[256];
    char dhcp_param_list[512];
} wei_data_t;

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

int lq_ipc_send_wei_data(uint32_t msg_type, const wei_data_t *entries, uint32_t count);