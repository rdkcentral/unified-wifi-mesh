/************************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:
  Copyright 2018 RDK Management
  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at
  http://www.apache.org/licenses/LICENSE-2.0
  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 **************************************************************************/

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include "lq_socket.h"
#include "util.h"


static int lq_ipc_fd = -1;

/* Close and reset the sender socket */
static void lq_ipc_reset_fd(void)
{
    if (lq_ipc_fd >= 0) {
        close(lq_ipc_fd);
        lq_ipc_fd = -1;
    }
}

/* Open UNIX Domain Socket (UDS) */
static int lq_ipc_open_fd(void)
{
    if (lq_ipc_fd >= 0)
        return 0;

    lq_ipc_fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (lq_ipc_fd < 0) {
        em_printfout("%s:%d UDS socket() creation failed: %s", __func__, __LINE__, strerror(errno));
        return -1;
    }

    /* Set send buffer size to handle burst data for active stations */
    int sndbuf = 4 * 1024 * 1024;
    setsockopt(lq_ipc_fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

    return 0;
}

static const char *lq_msg_type_str(uint32_t type)
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

static void lq_ipc_log_wei_entries(uint32_t msg_type, const wei_data_t *entries, uint32_t count)
{
    if (!entries || count == 0) return;

    for (uint32_t i = 0; i < count; i++) {
        em_printfout("%s [UDS-SEND] %s [%u/%u] STA_MAC=%s AP_MAC=%s VAP=%u Radio=%u SNR=%d "
                     "TxPkts=%lu RxPkts=%lu ConnectedTime=%lds",
            __func__, lq_msg_type_str(msg_type), i + 1, count,
            entries[i].mac_str,
            entries[i].ap_mac_str,
            entries[i].vap_index, entries[i].radio_index,
            entries[i].dev.cli_SNR, entries[i].dev.cli_PacketsSent,
            entries[i].dev.cli_PacketsReceived,
            (long)entries[i].total_connected_time.tv_sec);
    }
}

/* Encode wei_data_t payload as an lq_tlv_t packet over UDS */
static int build_tlv(uint32_t msg_type, const wei_data_t *entries,
                     uint32_t count, uint8_t *buf, size_t buf_sz)
{
    size_t data_sz = count * sizeof(wei_data_t);
    size_t needed  = sizeof(lq_tlv_t) + data_sz;

    if (needed > buf_sz) {
        em_printfout("%s:%d [UDS-TLV] Buffer overflow: needed %zu, available %zu",
            __func__, __LINE__, needed, buf_sz);
        return -1;
    }

    if (data_sz > UINT16_MAX) {
        em_printfout("%s:%d [UDS-TLV] Payload size %zu exceeds UINT16_MAX",
            __func__, __LINE__, data_sz);
        return -1;
    }

    lq_tlv_t *tlv = reinterpret_cast<lq_tlv_t *>(buf);
    tlv->type = static_cast<uint8_t>(msg_type);
    tlv->len  = static_cast<uint16_t>(data_sz);

    if (data_sz > 0 && entries != NULL) {
        memcpy(tlv->value, entries, data_sz);
    }

    return static_cast<int>(needed);
}

/* Main send function to transfer wei_data_t structures over UNIX Domain Socket */
int lq_ipc_send_wei_data(uint32_t msg_type, const wei_data_t *entries, uint32_t count)
{
    em_printfout("%s:%d [UDS-SEND] Sending msg_type=%s(%u) count=%u total_size=%zu",
        __func__, __LINE__, lq_msg_type_str(msg_type), msg_type,
        count, count * sizeof(wei_data_t));

    if (count > 0 && entries == NULL) {
        em_printfout("%s:%d [UDS-SEND] Error: null entries pointer with non-zero count", __func__, __LINE__);
        return -1;
    }

    lq_ipc_log_wei_entries(msg_type, entries, count);

    if (lq_ipc_open_fd() < 0) {
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, LQ_STATS_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    size_t data_sz  = static_cast<size_t>(count) * sizeof(wei_data_t);
    size_t alloc_sz = sizeof(lq_tlv_t) + data_sz;
    uint8_t *buf = static_cast<uint8_t *>(malloc(alloc_sz));
    if (!buf) {
        em_printfout("%s:%d malloc(%zu) failed", __func__, __LINE__, alloc_sz);
        return -1;
    }

    int tlv_len = build_tlv(msg_type, entries, count, buf, alloc_sz);
    if (tlv_len < 0) {
        free(buf);
        return -1;
    }

    ssize_t ret = -1;
    for (int attempt = 0; attempt < 2; attempt++) {
        ret = sendto(lq_ipc_fd, buf, static_cast<size_t>(tlv_len), MSG_DONTWAIT,
                     reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr));
        if (ret >= 0) {
            em_printfout("%s:%d [UDS-SEND] %s successfully sent %zd bytes over socket",
                __func__, __LINE__, lq_msg_type_str(msg_type), ret);
            break;
        }

        int err = errno;
        em_printfout("%s:%d [UDS-SEND] sendto(%s) failed: %s (attempt %d)",
            __func__, __LINE__, LQ_STATS_SOCKET_PATH, strerror(err), attempt + 1);

        /* Re-open socket and retry once if receiver restarted or socket dropped */
        if (attempt == 0 && (err == ENOENT || err == ECONNREFUSED || err == EAGAIN)) {
            lq_ipc_reset_fd();
            usleep(50000); // 50ms buffer
            if (lq_ipc_open_fd() < 0) {
                break;
            }
        } else {
            break;
        }
    }

    free(buf);
    return (ret < 0) ? -1 : 0;
}