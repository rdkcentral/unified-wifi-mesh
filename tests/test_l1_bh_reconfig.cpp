/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2025 RDK Management
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

/**
 * @file test_l1_bh_reconfig.cpp
 * @brief Unit tests for backhaul SSID reconfiguration leaf-first topology traversal.
 *
 * Simulates the mixed topology from BH_imp_checklist.md:
 *
 *   Controller --- CA (Co-located Agent)
 *                   |-- SA1 (Star Agent 1, depth 1)
 *                   |-- SA2 (Star Agent 2, depth 1)
 *                   |-- DA1 (depth 1) -> DA2 (depth 2) -> DA3 (depth 3, leaf)
 *                   +-- DA4 (depth 1) -> DA5 (depth 2) -> DA6 (depth 3, leaf)
 *
 * Tests verify:
 *   - is_bh_reconfig_leaf() identifies correct nodes per phase
 *   - mark_bh_leaves_processed() advances the tree phase by phase
 *   - is_bh_reconfig_complete() detects when all nodes are processed
 *   - reset_bh_reconfig() clears all processed flags
 *   - Leaf-first post-order: leaves -> depth-2 -> depth-1 -> root
 */

#include <gtest/gtest.h>
#include <stdio.h>
#include <string.h>
#include <vector>
#include <algorithm>
#include "em_network_topo.h"
#include "dm_easy_mesh.h"

/**
 * @brief Test fixture for backhaul reconfiguration mixed topology.
 *
 * Builds the tree using add_network_topo() (public API) with child_topos
 * parameter to create nested sub-trees. find_topology() matches by dm pointer.
 *
 * Tree structure:
 *   root (CA)
 *   |-- SA1  (star, leaf)
 *   |-- SA2  (star, leaf)
 *   |-- DA1  (daisy depth 1)
 *   |   +-- DA2  (daisy depth 2)
 *   |       +-- DA3  (daisy depth 3, leaf)
 *   +-- DA4  (daisy depth 1)
 *       +-- DA5  (daisy depth 2)
 *           +-- DA6  (daisy depth 3, leaf)
 */
class BhReconfigMixedTopoTest : public ::testing::Test {
protected:
    dm_easy_mesh_t *dm_root;
    dm_easy_mesh_t *dm_sa1, *dm_sa2;
    dm_easy_mesh_t *dm_da1, *dm_da2, *dm_da3;
    dm_easy_mesh_t *dm_da4, *dm_da5, *dm_da6;
    em_network_topo_t *topo_root;

    static void set_dm_mac(dm_easy_mesh_t *dm, unsigned char id) {
        memset(&dm->m_device, 0, sizeof(dm->m_device));
        unsigned char mac[6] = {0x02, id, 0x00, 0x00, 0x00, 0x00};
        memcpy(dm->m_device.m_device_info.intf.mac, mac, 6);
        dm->m_num_bss = 0;
    }

    void SetUp() override {
        dm_root = new dm_easy_mesh_t{};
        dm_sa1  = new dm_easy_mesh_t{};
        dm_sa2  = new dm_easy_mesh_t{};
        dm_da1  = new dm_easy_mesh_t{};
        dm_da2  = new dm_easy_mesh_t{};
        dm_da3  = new dm_easy_mesh_t{};
        dm_da4  = new dm_easy_mesh_t{};
        dm_da5  = new dm_easy_mesh_t{};
        dm_da6  = new dm_easy_mesh_t{};

        set_dm_mac(dm_root, 0x10);
        set_dm_mac(dm_sa1,  0x21);
        set_dm_mac(dm_sa2,  0x22);
        set_dm_mac(dm_da1,  0x31);
        set_dm_mac(dm_da2,  0x32);
        set_dm_mac(dm_da3,  0x33);
        set_dm_mac(dm_da4,  0x41);
        set_dm_mac(dm_da5,  0x42);
        set_dm_mac(dm_da6,  0x43);

        topo_root = new em_network_topo_t(dm_root);

        // Star agents: leaf nodes directly under root
        topo_root->add_network_topo(dm_sa1, nullptr, 0);
        topo_root->add_network_topo(dm_sa2, nullptr, 0);

        // Daisy chain 1: DA1 -> DA2 -> DA3
        // Build bottom-up using add_network_topo with child_topos.
        // add_network_topo(dm, child_topos, count) creates a new node for dm
        // and memcpy's child_topos pointers into it.
        em_network_topo_t *sub_da2 = new em_network_topo_t(dm_da2);
        sub_da2->add_network_topo(dm_da3, nullptr, 0);  // DA3 leaf under DA2
        em_network_topo_t *da2_arr[] = { sub_da2 };
        topo_root->add_network_topo(dm_da1, da2_arr, 1);  // DA1 under root, with DA2 subtree

        // Daisy chain 2: DA4 -> DA5 -> DA6 (same pattern)
        em_network_topo_t *sub_da5 = new em_network_topo_t(dm_da5);
        sub_da5->add_network_topo(dm_da6, nullptr, 0);  // DA6 leaf under DA5
        em_network_topo_t *da5_arr[] = { sub_da5 };
        topo_root->add_network_topo(dm_da4, da5_arr, 1);  // DA4 under root, with DA5 subtree
    }

    void TearDown() override {
        delete topo_root;
        delete dm_root;
        delete dm_sa1;  delete dm_sa2;
        delete dm_da1;  delete dm_da2;  delete dm_da3;
        delete dm_da4;  delete dm_da5;  delete dm_da6;
    }

    em_network_topo_t *find(dm_easy_mesh_t *dm) {
        return topo_root->find_topology(dm);
    }

    // Collect all current leaves by checking every dm in the tree.
    std::vector<dm_easy_mesh_t *> get_current_leaves() {
        std::vector<dm_easy_mesh_t *> leaves;
        dm_easy_mesh_t *all_dms[] = {
            dm_root, dm_sa1, dm_sa2,
            dm_da1, dm_da2, dm_da3,
            dm_da4, dm_da5, dm_da6
        };
        for (auto *dm : all_dms) {
            em_network_topo_t *node = find(dm);
            if (node != NULL && node->is_bh_reconfig_leaf()) {
                leaves.push_back(dm);
            }
        }
        return leaves;
    }

    bool leaves_contain(const std::vector<dm_easy_mesh_t *> &leaves, dm_easy_mesh_t *dm) {
        return std::find(leaves.begin(), leaves.end(), dm) != leaves.end();
    }
};

/**
 * @brief Verify find_topology returns correct node for each dm.
 */
TEST_F(BhReconfigMixedTopoTest, find_topology_all_nodes)
{
    EXPECT_NE(find(dm_root), nullptr);
    EXPECT_NE(find(dm_sa1),  nullptr);
    EXPECT_NE(find(dm_sa2),  nullptr);
    EXPECT_NE(find(dm_da1),  nullptr);
    EXPECT_NE(find(dm_da2),  nullptr);
    EXPECT_NE(find(dm_da3),  nullptr);
    EXPECT_NE(find(dm_da4),  nullptr);
    EXPECT_NE(find(dm_da5),  nullptr);
    EXPECT_NE(find(dm_da6),  nullptr);

    EXPECT_EQ(find(dm_root)->get_data_model(), dm_root);
    EXPECT_EQ(find(dm_da3)->get_data_model(), dm_da3);
    EXPECT_EQ(find(dm_da6)->get_data_model(), dm_da6);
}

/**
 * @brief Verify initial leaf identification in mixed topology.
 *
 * Before any processing, the leaves should be: SA1, SA2, DA3, DA6
 */
TEST_F(BhReconfigMixedTopoTest, initial_leaves_are_correct)
{
    auto leaves = get_current_leaves();
    ASSERT_EQ(leaves.size(), 4u);

    EXPECT_TRUE(leaves_contain(leaves, dm_sa1))  << "SA1 should be a leaf";
    EXPECT_TRUE(leaves_contain(leaves, dm_sa2))  << "SA2 should be a leaf";
    EXPECT_TRUE(leaves_contain(leaves, dm_da3))  << "DA3 should be a leaf";
    EXPECT_TRUE(leaves_contain(leaves, dm_da6))  << "DA6 should be a leaf";

    EXPECT_FALSE(find(dm_root)->is_bh_reconfig_leaf()) << "Root should NOT be a leaf";
    EXPECT_FALSE(find(dm_da1)->is_bh_reconfig_leaf())  << "DA1 should NOT be a leaf";
    EXPECT_FALSE(find(dm_da2)->is_bh_reconfig_leaf())  << "DA2 should NOT be a leaf";
    EXPECT_FALSE(find(dm_da4)->is_bh_reconfig_leaf())  << "DA4 should NOT be a leaf";
    EXPECT_FALSE(find(dm_da5)->is_bh_reconfig_leaf())  << "DA5 should NOT be a leaf";
}

/**
 * @brief Phase 1: mark leaves, verify DA2/DA5 become new leaves.
 */
TEST_F(BhReconfigMixedTopoTest, phase1_mark_advances_to_depth2)
{
    topo_root->mark_bh_leaves_processed();

    auto leaves = get_current_leaves();
    ASSERT_EQ(leaves.size(), 2u);
    EXPECT_TRUE(leaves_contain(leaves, dm_da2)) << "DA2 should now be a leaf";
    EXPECT_TRUE(leaves_contain(leaves, dm_da5)) << "DA5 should now be a leaf";

    EXPECT_FALSE(find(dm_sa1)->is_bh_reconfig_leaf());
    EXPECT_FALSE(find(dm_sa2)->is_bh_reconfig_leaf());
    EXPECT_FALSE(find(dm_da3)->is_bh_reconfig_leaf());
    EXPECT_FALSE(find(dm_da6)->is_bh_reconfig_leaf());
    EXPECT_FALSE(topo_root->is_bh_reconfig_complete());
}

/**
 * @brief Phase 2: mark depth-2 agents, verify DA1/DA4 become new leaves.
 */
TEST_F(BhReconfigMixedTopoTest, phase2_mark_advances_to_depth1)
{
    topo_root->mark_bh_leaves_processed();  // Phase 1
    topo_root->mark_bh_leaves_processed();  // Phase 2

    auto leaves = get_current_leaves();
    ASSERT_EQ(leaves.size(), 2u);
    EXPECT_TRUE(leaves_contain(leaves, dm_da1)) << "DA1 should now be a leaf";
    EXPECT_TRUE(leaves_contain(leaves, dm_da4)) << "DA4 should now be a leaf";

    EXPECT_FALSE(find(dm_root)->is_bh_reconfig_leaf());
    EXPECT_FALSE(topo_root->is_bh_reconfig_complete());
}

/**
 * @brief Phase 3: mark depth-1 daisy agents, verify root becomes a leaf.
 */
TEST_F(BhReconfigMixedTopoTest, phase3_mark_advances_to_root)
{
    topo_root->mark_bh_leaves_processed();  // Phase 1
    topo_root->mark_bh_leaves_processed();  // Phase 2
    topo_root->mark_bh_leaves_processed();  // Phase 3

    auto leaves = get_current_leaves();
    ASSERT_EQ(leaves.size(), 1u);
    EXPECT_EQ(leaves[0], dm_root) << "Root should be the only remaining leaf";
    EXPECT_FALSE(topo_root->is_bh_reconfig_complete());
}

/**
 * @brief Phase 4: mark root, verify reconfig is complete.
 */
TEST_F(BhReconfigMixedTopoTest, phase4_mark_completes_reconfig)
{
    topo_root->mark_bh_leaves_processed();  // Phase 1: SA1, SA2, DA3, DA6
    topo_root->mark_bh_leaves_processed();  // Phase 2: DA2, DA5
    topo_root->mark_bh_leaves_processed();  // Phase 3: DA1, DA4
    topo_root->mark_bh_leaves_processed();  // Phase 4: Root

    EXPECT_TRUE(topo_root->is_bh_reconfig_complete());
}

/**
 * @brief Full phase ordering: verify correct agents collected per phase.
 *
 * Expected order:
 *   Phase 1: {SA1, SA2, DA3, DA6}
 *   Phase 2: {DA2, DA5}
 *   Phase 3: {DA1, DA4}
 *   Phase 4: {Root}
 */
TEST_F(BhReconfigMixedTopoTest, full_phase_ordering)
{
    // Phase 1
    auto p1 = get_current_leaves();
    ASSERT_EQ(p1.size(), 4u);
    EXPECT_TRUE(leaves_contain(p1, dm_sa1));
    EXPECT_TRUE(leaves_contain(p1, dm_sa2));
    EXPECT_TRUE(leaves_contain(p1, dm_da3));
    EXPECT_TRUE(leaves_contain(p1, dm_da6));
    topo_root->mark_bh_leaves_processed();

    // Phase 2
    auto p2 = get_current_leaves();
    ASSERT_EQ(p2.size(), 2u);
    EXPECT_TRUE(leaves_contain(p2, dm_da2));
    EXPECT_TRUE(leaves_contain(p2, dm_da5));
    topo_root->mark_bh_leaves_processed();

    // Phase 3
    auto p3 = get_current_leaves();
    ASSERT_EQ(p3.size(), 2u);
    EXPECT_TRUE(leaves_contain(p3, dm_da1));
    EXPECT_TRUE(leaves_contain(p3, dm_da4));
    topo_root->mark_bh_leaves_processed();

    // Phase 4
    auto p4 = get_current_leaves();
    ASSERT_EQ(p4.size(), 1u);
    EXPECT_EQ(p4[0], dm_root);
    topo_root->mark_bh_leaves_processed();

    EXPECT_TRUE(topo_root->is_bh_reconfig_complete());
}

/**
 * @brief Verify reset_bh_reconfig clears all processed flags.
 */
TEST_F(BhReconfigMixedTopoTest, reset_restores_initial_state)
{
    topo_root->mark_bh_leaves_processed();
    topo_root->mark_bh_leaves_processed();
    topo_root->reset_bh_reconfig();

    auto leaves = get_current_leaves();
    ASSERT_EQ(leaves.size(), 4u);
    EXPECT_TRUE(leaves_contain(leaves, dm_sa1));
    EXPECT_TRUE(leaves_contain(leaves, dm_sa2));
    EXPECT_TRUE(leaves_contain(leaves, dm_da3));
    EXPECT_TRUE(leaves_contain(leaves, dm_da6));
    EXPECT_FALSE(topo_root->is_bh_reconfig_complete());
}

/**
 * @brief Verify active flag management.
 */
TEST_F(BhReconfigMixedTopoTest, active_flag_management)
{
    EXPECT_FALSE(topo_root->is_bh_reconfig_active());
    topo_root->set_bh_reconfig_active(true);
    EXPECT_TRUE(topo_root->is_bh_reconfig_active());
    topo_root->set_bh_reconfig_active(false);
    EXPECT_FALSE(topo_root->is_bh_reconfig_active());
}

/**
 * @brief Verify marking an already-complete tree is a safe no-op.
 */
TEST_F(BhReconfigMixedTopoTest, mark_after_complete_is_noop)
{
    for (int i = 0; i < 4; i++)
        topo_root->mark_bh_leaves_processed();
    ASSERT_TRUE(topo_root->is_bh_reconfig_complete());

    topo_root->mark_bh_leaves_processed();  // Extra call
    EXPECT_TRUE(topo_root->is_bh_reconfig_complete());
    EXPECT_EQ(get_current_leaves().size(), 0u);
}

/**
 * @brief Verify reset after full completion allows re-run.
 */
TEST_F(BhReconfigMixedTopoTest, reset_after_complete_allows_rerun)
{
    for (int i = 0; i < 4; i++)
        topo_root->mark_bh_leaves_processed();
    ASSERT_TRUE(topo_root->is_bh_reconfig_complete());

    topo_root->reset_bh_reconfig();
    EXPECT_FALSE(topo_root->is_bh_reconfig_complete());

    auto leaves = get_current_leaves();
    ASSERT_EQ(leaves.size(), 4u);
    EXPECT_TRUE(leaves_contain(leaves, dm_sa1));
    EXPECT_TRUE(leaves_contain(leaves, dm_sa2));
    EXPECT_TRUE(leaves_contain(leaves, dm_da3));
    EXPECT_TRUE(leaves_contain(leaves, dm_da6));
}
