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
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <pthread.h>
#include "lq_listener.h"
#include "lq_socket.h"
#include "util.h"

/* Largest datagram lq_ipc_sender.c can send is
 * LQ_IPC_BATCH_SIZE(16) * sizeof(stats_arg_t); give ourselves headroom. */
#define LQ_LISTENER_RECV_BUF_SZ (64 * 1024)

static pthread_t       s_lq_listener_tid;
static int             s_lq_listener_fd = -1;
static lq_raw_data_cb_t s_lq_listener_cb = NULL;

/* Validates the lq_tlv_t framing only; payload interpretation is the
 * caller's responsibility. */
static void lq_listener_handle_datagram(const uint8_t *buf, ssize_t n)
{
    if (n < static_cast<ssize_t>(sizeof(lq_tlv_t))) {
        em_printfout("%s:%d [LQ-LISTEN] Datagram too small: %zd bytes", __func__, __LINE__, n);
        return;
    }

    const lq_tlv_t *tlv = reinterpret_cast<const lq_tlv_t *>(buf);
    size_t payload_len = tlv->len;

    if (static_cast<ssize_t>(sizeof(lq_tlv_t) + payload_len) > n) {
        em_printfout("%s:%d [LQ-LISTEN] Malformed datagram: type=%u len=%zu received=%zd",
            __func__, __LINE__, tlv->type, payload_len, n);
        return;
    }

    if (s_lq_listener_cb) {
        s_lq_listener_cb(tlv->type, tlv->value, payload_len);
    }
}

static void *lq_listener_thread(void *arg)
{
    (void)arg;
    uint8_t *buf = new uint8_t[LQ_LISTENER_RECV_BUF_SZ];

    while (true) {
        ssize_t n = recv(s_lq_listener_fd, buf, LQ_LISTENER_RECV_BUF_SZ, 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            em_printfout("%s:%d [LQ-LISTEN] recv() failed: %s", __func__, __LINE__, strerror(errno));
            break;
        }
        lq_listener_handle_datagram(buf, n);
    }

    delete[] buf;
    return NULL;
}

int lq_listener_start(lq_raw_data_cb_t cb)
{
    if (s_lq_listener_fd >= 0) {
        return 0; /* already started */
    }

    s_lq_listener_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (s_lq_listener_fd < 0) {
        em_printfout("%s:%d [LQ-LISTEN] socket() failed: %s", __func__, __LINE__, strerror(errno));
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, LQ_STATS_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    /* Remove a stale socket file from a previous run before binding. */
    unlink(LQ_STATS_SOCKET_PATH);

    if (bind(s_lq_listener_fd, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) < 0) {
        em_printfout("%s:%d [LQ-LISTEN] bind(%s) failed: %s", __func__, __LINE__,
            LQ_STATS_SOCKET_PATH, strerror(errno));
        close(s_lq_listener_fd);
        s_lq_listener_fd = -1;
        return -1;
    }

    s_lq_listener_cb = cb;

    if (pthread_create(&s_lq_listener_tid, NULL, lq_listener_thread, NULL) != 0) {
        em_printfout("%s:%d [LQ-LISTEN] pthread_create() failed: %s", __func__, __LINE__, strerror(errno));
        close(s_lq_listener_fd);
        s_lq_listener_fd = -1;
        return -1;
    }

    pthread_detach(s_lq_listener_tid);
    em_printfout("%s:%d [LQ-LISTEN] Listening on %s", __func__, __LINE__, LQ_STATS_SOCKET_PATH);
    return 0;
}
