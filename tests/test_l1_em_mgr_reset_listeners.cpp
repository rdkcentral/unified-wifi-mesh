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
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <functional>
#include <future>
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
#include <unistd.h>

#include "em.h"
#include "em_mgr.h"

/*
 * em_t::set_fd() (test accessor) sets the descriptor a node listens on; normally only start_al_interface() does, with a raw socket.
 *
 * em_mgr_t::reset_listeners(): only AL nodes whose descriptor is a valid fd_set index (0 .. FD_SETSIZE - 1) are put in
 * the read set and counted for highest_fd. FD_SET() of -1 or FD_SETSIZE writes outside the fd_set.
 */

class ResetListenersTestMgr : public em_mgr_t {
public:
    std::vector<std::pair<std::string, em_t *> > owned;
    std::mutex lens_lock;
    std::vector<unsigned int> lens;          /* length of every frame nodes_listener() handed to proto_process() */

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
    /* proto_process() calls this first and returns when it gets NULL, so it records the frames without parsing them */
    em_t *find_em_for_msg_type(unsigned char *, unsigned int len, em_t *) override {
        std::lock_guard<std::mutex> g(lens_lock);
        lens.push_back(len);
        return nullptr;
    }
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
    em->set_fd(fd);
    mgr.owned.push_back(std::make_pair(std::string(key), em));
    hash_map_put(mgr.m_em_map, strdup(key), em);
}
static size_t frames_parsed(ResetListenersTestMgr &mgr) { std::lock_guard<std::mutex> g(mgr.lens_lock); return mgr.lens.size(); }
static std::vector<unsigned int> frame_lens(ResetListenersTestMgr &mgr) { std::lock_guard<std::mutex> g(mgr.lens_lock); return mgr.lens; }

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

#ifndef AL_SAP
/*
 * nodes_listener() reads a frame from every ready AL descriptor and hands it to proto_process() only when read() returned
 * a positive length: -1 (error) converted to unsigned would be a 4 GB frame, 0 means end of file. The nodes listen on real
 * descriptors whose read() result is known: a directory (read fails with EISDIR), /dev/null (read returns 0) and a pipe
 * (read returns what was written). select() reports the directory and /dev/null ready all the time.
 *
 * The loop only ends when select() fails, so the listener runs on a thread and the descriptors are closed to stop it.
 * Nothing is timed: the test writes to the pipe and waits until the frame arrives at proto_process(). The silent node is
 * visited in every pass of the loop, so once a second frame (written after the first was seen) arrives, a complete pass
 * has read the silent descriptor. Waits and the shutdown are bounded.
 */
class em_mgr_nodes_listener_Test : public ::testing::Test {
protected:
    ResetListenersTestMgr *mgr = nullptr;
    std::thread worker;
    std::future<void> done;
    bool hung = false;
    std::vector<int> fds;

    void SetUp() override {
        mgr = new ResetListenersTestMgr();
        mgr->m_timeout = 10;
    }
    void TearDown() override {
        stop_listener();
        for (int fd : fds) {
            close(fd);
        }
        fds.clear();
        if (!hung) {
            delete mgr;      /* a listener that did not stop still uses it: leave it alone (the test already failed) */
        }
    }

    int track(int fd) { fds.push_back(fd); return fd; }

    /* reset_listeners() excludes a descriptor outside the fd_set, and closing it could then not end the loop */
    ::testing::AssertionResult usable(int fd) {
        if (fd < 0 || fd >= FD_SETSIZE) {
            return ::testing::AssertionFailure() << "descriptor " << fd << " cannot be used by the listener";
        }
        return ::testing::AssertionSuccess();
    }

    void start_listener() {
        auto p = std::make_shared<std::promise<void> >();
        done = p->get_future();
        worker = std::thread([this, p]() { mgr->nodes_listener(); p->set_value(); });
    }
    bool wait_for_frames(size_t n) {
        for (int i = 0; i < 1000; i++) {
            if (frames_parsed(*mgr) >= n) {
                return true;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        return false;
    }
    /* closing the descriptors makes select() fail, which ends the loop */
    void stop_listener() {
        if (!worker.joinable()) {
            return;
        }
        for (int fd : fds) {
            close(fd);
        }
        fds.clear();
        if (done.wait_for(std::chrono::seconds(5)) == std::future_status::timeout) {
            hung = true;
            ADD_FAILURE() << "nodes_listener() did not stop";
            worker.detach();
        } else {
            worker.join();
        }
    }

    /* silent_fd (>= 0): a node whose read() never gives a positive length; plus a pipe node that carries 5 and then 3 bytes */
    void check_only_positive_reads(int silent_fd) {
        int p[2];
        ASSERT_EQ(pipe(p), 0);
        track(p[0]);
        track(p[1]);
        ASSERT_TRUE(usable(p[0]));
        if (silent_fd >= 0) {
            track(silent_fd);
            ASSERT_TRUE(usable(silent_fd));
            add_em(*mgr, "al-silent", silent_fd, true);
        }
        add_em(*mgr, "al-pipe", p[0], true);

        start_listener();
        ASSERT_EQ(write(p[1], "hello", 5), 5);
        ASSERT_TRUE(wait_for_frames(1));
        ASSERT_EQ(write(p[1], "abc", 3), 3);
        ASSERT_TRUE(wait_for_frames(2));
        stop_listener();

        std::vector<unsigned int> expected;
        expected.push_back(5);
        expected.push_back(3);
        EXPECT_EQ(frame_lens(*mgr), expected);
    }
};

TEST_F(em_mgr_nodes_listener_Test, ReadErrorDoesNotReachTheParser) {
    int fd = open("/", O_RDONLY);       /* read() fails with EISDIR */
    ASSERT_GE(fd, 0);
    check_only_positive_reads(fd);
}

TEST_F(em_mgr_nodes_listener_Test, EndOfFileDoesNotReachTheParser) {
    int fd = open("/dev/null", O_RDONLY);       /* read() returns 0 */
    ASSERT_GE(fd, 0);
    check_only_positive_reads(fd);
}

TEST_F(em_mgr_nodes_listener_Test, PositiveReadsReachTheParserWithTheirLength) {
    check_only_positive_reads(-1);
}
#endif
