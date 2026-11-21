/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2026 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <gtest/gtest.h>
#include <algorithm>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>
#include <pthread.h>
#include <sys/select.h>

/* em_t keeps its socket descriptor in a private member (m_fd) that only start_al_interface() sets, and that needs a
 * raw socket. This file is the only one that opens access, so the descriptor of a node can be set to the values under test. */
#define private public
#include "em.h"
#undef private
#include "em_mgr.h"

/*
 * em_mgr_t::reset_listeners(): only AL nodes whose descriptor is a valid fd_set index (0 .. FD_SETSIZE - 1) are put in
 * the read set and counted for highest_fd. FD_SET() of -1 or FD_SETSIZE writes outside the fd_set.
 */

class ResetListenersTestMgr : public em_mgr_t {
public:
    std::vector<std::pair<std::string, em_t *> > owned;

    ResetListenersTestMgr() {
        pthread_mutex_init(&m_mutex, nullptr);
        m_em_map = hash_map_create();
    }
    ~ResetListenersTestMgr() override {
        for (auto &p : owned) {
            hash_map_remove(m_em_map, p.first.c_str());
            delete p.second;
        }
        if (m_em_map != nullptr) {
            hash_map_destroy(m_em_map);
        }
        pthread_mutex_destroy(&m_mutex);
    }

    bool is_data_model_initialized() override { return true; }
    em_t *find_em_for_msg_type(unsigned char *, unsigned int, em_t *) override { return nullptr; }
    int data_model_init(const char *) override { return 0; }
    int orch_init() override { return 0; }
    void input_listener() override {}
    void start_complete() override {}
    void handle_event(em_event_t *) override {}
    void handle_5s_tick() override {}
    void handle_2s_tick() override {}
    void handle_1s_tick() override {}
    void handle_250ms_tick() override {}
    void io(void *, bool) override {}
    void update_network_topology() override {}
    void publish_network_topology() override {}
    dm_easy_mesh_t *get_first_dm() override { return nullptr; }
    dm_easy_mesh_t *get_next_dm(dm_easy_mesh_t *) override { return nullptr; }
    dm_easy_mesh_t *get_data_model(const char *, const unsigned char *) override { return nullptr; }
    dm_easy_mesh_t *create_data_model(const char *, const em_interface_t *, em_profile_type_t) override { return nullptr; }
    void delete_data_model(const char *, const unsigned char *) override {}
    void delete_all_data_models() override {}
    int update_tables(dm_easy_mesh_t *) override { return 0; }
    int load_net_ssid_table() override { return 0; }
    void debug_probe() override {}
    em_service_type_t get_service_type() override { return em_service_type_ctrl; }
};

/* builds a node (the constructor starts no thread; only init() does) with the given AL flag and descriptor and registers it */
static void add_em(ResetListenersTestMgr &mgr, const char *key, int fd, bool al)
{
    static dm_easy_mesh_t dm;
    em_interface_t ruid;
    memset(&ruid, 0, sizeof(ruid));
    snprintf(ruid.name, sizeof(ruid.name), "wlan0");
    ruid.mac[0] = 0x02;
    ruid.mac[5] = static_cast<unsigned char>(mgr.owned.size() + 1);
    em_t *em = new em_t(&ruid, em_freq_band_24, &dm, &mgr, em_profile_type_1, em_service_type_ctrl, false);
    em->set_al_type(al);
    em->m_fd = fd;
    mgr.owned.push_back(std::make_pair(std::string(key), em));
    hash_map_put(mgr.m_em_map, strdup(key), em);
}

class em_mgr_reset_listeners_Test : public ::testing::Test {
protected:
    ResetListenersTestMgr mgr;
    static const size_t WINDOW = 16;
    unsigned char before_lo[WINDOW], before_hi[WINDOW];

    unsigned char *rset_bytes() { return reinterpret_cast<unsigned char *>(&mgr.m_rset); }

    /* the bytes just in front of and behind m_rset: FD_SET(-1) / FD_SET(FD_SETSIZE) land there */
    void snapshot() {
        memcpy(before_lo, rset_bytes() - WINDOW, WINDOW);
        memcpy(before_hi, rset_bytes() + sizeof(fd_set), WINDOW);
    }
    void expect_neighbours_untouched() {
        EXPECT_EQ(memcmp(before_lo, rset_bytes() - WINDOW, WINDOW), 0) << "bytes in front of m_rset were written";
        EXPECT_EQ(memcmp(before_hi, rset_bytes() + sizeof(fd_set), WINDOW), 0) << "bytes behind m_rset were written";
    }
    int bits_set() {
        int n = 0;
        for (int fd = 0; fd < FD_SETSIZE; fd++) {
            if (FD_ISSET(fd, &mgr.m_rset)) n++;
        }
        return n;
    }
    int run() {
        snapshot();
        int highest = mgr.reset_listeners();
        expect_neighbours_untouched();
        return highest;
    }
};

TEST_F(em_mgr_reset_listeners_Test, NegativeDescriptorIsExcluded) {
    add_em(mgr, "al-1", -1, true);
    EXPECT_EQ(run(), 0);
    EXPECT_EQ(bits_set(), 0);
}

TEST_F(em_mgr_reset_listeners_Test, DescriptorEqualToFdSetsizeIsExcluded) {
    add_em(mgr, "al-1", FD_SETSIZE, true);
    EXPECT_EQ(run(), 0);
    EXPECT_EQ(bits_set(), 0);
}

TEST_F(em_mgr_reset_listeners_Test, DescriptorsFarOutsideTheSetAreExcluded) {
    add_em(mgr, "al-1", FD_SETSIZE + 1, true);
    add_em(mgr, "al-2", 100000, true);
    add_em(mgr, "al-3", INT_MAX, true);
    add_em(mgr, "al-4", INT_MIN, true);
    EXPECT_EQ(run(), 0);
    EXPECT_EQ(bits_set(), 0);
}

TEST_F(em_mgr_reset_listeners_Test, LargestValidDescriptorIsKept) {
    add_em(mgr, "al-1", FD_SETSIZE - 1, true);
    EXPECT_EQ(run(), FD_SETSIZE - 1);
    EXPECT_TRUE(FD_ISSET(FD_SETSIZE - 1, &mgr.m_rset));
    EXPECT_EQ(bits_set(), 1);
}

TEST_F(em_mgr_reset_listeners_Test, DescriptorZeroIsKeptButDoesNotRaiseHighestFd) {
    add_em(mgr, "al-1", 0, true);
    EXPECT_EQ(run(), 0);
    EXPECT_TRUE(FD_ISSET(0, &mgr.m_rset));
    EXPECT_EQ(bits_set(), 1);
}

TEST_F(em_mgr_reset_listeners_Test, MixedValidAndRejectedDescriptors) {
    add_em(mgr, "al-1", -1, true);
    add_em(mgr, "al-2", 5, true);
    add_em(mgr, "al-3", FD_SETSIZE, true);
    add_em(mgr, "al-4", FD_SETSIZE - 1, true);
    add_em(mgr, "al-5", 7, true);
    add_em(mgr, "al-6", INT_MAX, true);
    EXPECT_EQ(run(), FD_SETSIZE - 1);
    EXPECT_TRUE(FD_ISSET(5, &mgr.m_rset));
    EXPECT_TRUE(FD_ISSET(7, &mgr.m_rset));
    EXPECT_TRUE(FD_ISSET(FD_SETSIZE - 1, &mgr.m_rset));
    EXPECT_EQ(bits_set(), 3);
}

TEST_F(em_mgr_reset_listeners_Test, RejectedDescriptorDoesNotHideAValidOne) {
    add_em(mgr, "al-1", FD_SETSIZE, true);
    add_em(mgr, "al-2", 9, true);
    EXPECT_EQ(run(), 9);
    EXPECT_TRUE(FD_ISSET(9, &mgr.m_rset));
    EXPECT_EQ(bits_set(), 1);
}

TEST_F(em_mgr_reset_listeners_Test, NonAlNodeIsExcludedEvenWithAValidDescriptor) {
    add_em(mgr, "radio-1", 20, false);
    add_em(mgr, "al-1", 6, true);
    EXPECT_EQ(run(), 6);
    EXPECT_FALSE(FD_ISSET(20, &mgr.m_rset));
    EXPECT_TRUE(FD_ISSET(6, &mgr.m_rset));
    EXPECT_EQ(bits_set(), 1);
}
