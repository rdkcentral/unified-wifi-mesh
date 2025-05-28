# If not stated otherwise in this file or this component's Licenses.txt
# file the following copyright and licenses apply:
#
# Copyright 2025 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################
AM_CFLAGS = -D_ANSC_LINUX
AM_CFLAGS += -D_ANSC_USER
AM_CFLAGS += -D_ANSC_LITTLE_ENDIAN_
 
ACLOCAL_AMFLAGS = -I m4
hardware_platform = i686-linux-gnu
bin_PROGRAMS = onewifi_em_ctrl
 
onewifi_em_ctrl_CPPFLAGS = \
    -I$(top_srcdir)/inc \
    -I$(top_srcdir)/src/utils \
    -I$(top_srcdir)/src/util \
    -I$(top_srcdir)/src/util_crypto \
    -I$(top_srcdir)/OneWifi/include \
    -I$(top_srcdir)/OneWifi/lib/log  \
    -I$(top_srcdir)/OneWifi/lib/ds  \
    -I$(top_srcdir)/OneWifi/source/utils \
    -I$(top_srcdir)/OneWifi/source/platform/rdkb \
    -I$(top_srcdir)/OneWifi/source/platform/common \
    -DUNIT_TEST

onewifi_em_ctrl_CXXFLAGS = $(INCLUDEDIRS) -g -DUNIT_TEST -Wall -Wextra -pedantic -Wpedantic -Wpointer-arith -Wcast-qual -Wcast-align -Wstrict-aliasing -fno-common -Wctor-dtor-privacy -Wold-style-cast -Woverloaded-virtual -Wsign-promo -Wstrict-null-sentinel -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -pie -ftrapv -Wformat=2 -Wformat-security -Wuninitialized -Winit-self -Wconversion -Wsign-conversion -Weffc++ -Wno-unused-parameter -std=c++17 -fsanitize=address -fsanitize=undefined #-Werror -O2

onewifi_em_ctrl_SOURCES =  \
     $(top_srcdir)/src/em/em.cpp \
     $(top_srcdir)/src/em/em_mgr.cpp \
     $(top_srcdir)/src/em/em_msg.cpp \
     $(top_srcdir)/src/em/em_onewifi.cpp \
     $(top_srcdir)/src/em/em_sm.cpp \
     $(top_srcdir)/src/em/em_net_node.cpp \
     $(top_srcdir)/src/em/config/em_configuration.cpp \
     $(top_srcdir)/src/em/prov/easyconnect/ec_configurator.cpp \
     $(top_srcdir)/src/em/prov/easyconnect/ec_crypto.cpp \
     $(top_srcdir)/src/em/prov/easyconnect/ec_ctrl_configurator.cpp \
     $(top_srcdir)/src/em/prov/easyconnect/ec_enrollee.cpp \
     $(top_srcdir)/src/em/prov/easyconnect/ec_manager.cpp \
     $(top_srcdir)/src/em/prov/easyconnect/ec_pa_configurator.cpp \
     $(top_srcdir)/src/em/prov/easyconnect/ec_util.cpp \
     $(top_srcdir)/src/em/prov/em_provisioning.cpp \
     $(top_srcdir)/src/em/disc/em_discovery.cpp \
     $(top_srcdir)/src/em/channel/em_channel.cpp  \
     $(top_srcdir)/src/em/capability/em_capability.cpp \
     $(top_srcdir)/src/em/metrics/em_metrics.cpp \
     $(top_srcdir)/src/em/steering/em_steering.cpp \
     $(top_srcdir)/src/em/policy_cfg/em_policy_cfg.cpp \
     $(top_srcdir)/src/em/crypto/em_crypto.cpp \
     $(top_srcdir)/src/cmd/em_cmd_ap_cap.cpp \
     $(top_srcdir)/src/cmd/em_cmd_cfg_renew.cpp \
     $(top_srcdir)/src/cmd/em_cmd_channel_pref_query.cpp \
     $(top_srcdir)/src/cmd/em_cmd_client_cap.cpp \
     $(top_srcdir)/src/cmd/em_cmd.cpp \
     $(top_srcdir)/src/cmd/em_cmd_dev_init.cpp \
     $(top_srcdir)/src/cmd/em_cmd_dev_test.cpp \
     $(top_srcdir)/src/cmd/em_cmd_em_config.cpp \
     $(top_srcdir)/src/cmd/em_cmd_exec.cpp \
     $(top_srcdir)/src/cmd/em_cmd_get_channel.cpp \
     $(top_srcdir)/src/cmd/em_cmd_get_device.cpp \
     $(top_srcdir)/src/cmd/em_cmd_get_network.cpp \
     $(top_srcdir)/src/cmd/em_cmd_get_radio.cpp \
     $(top_srcdir)/src/cmd/em_cmd_get_ssid.cpp \
     $(top_srcdir)/src/cmd/em_cmd_onewifi_cb.cpp \
     $(top_srcdir)/src/cmd/em_cmd_op_channel_report.cpp \
     $(top_srcdir)/src/cmd/em_cmd_remove_device.cpp \
     $(top_srcdir)/src/cmd/em_cmd_reset.cpp \
     $(top_srcdir)/src/cmd/em_cmd_scan_channel.cpp \
     $(top_srcdir)/src/cmd/em_cmd_set_channel.cpp \
     $(top_srcdir)/src/cmd/em_cmd_set_policy.cpp \
     $(top_srcdir)/src/cmd/em_cmd_set_radio.cpp \
     $(top_srcdir)/src/cmd/em_cmd_set_ssid.cpp \
     $(top_srcdir)/src/cmd/em_cmd_sta_assoc.cpp \
     $(top_srcdir)/src/cmd/em_cmd_sta_disassoc.cpp \
     $(top_srcdir)/src/cmd/em_cmd_sta_link_metrics.cpp \
     $(top_srcdir)/src/cmd/em_cmd_sta_list.cpp \
     $(top_srcdir)/src/cmd/em_cmd_start_dpp.cpp \
     $(top_srcdir)/src/cmd/em_cmd_sta_steer.cpp \
     $(top_srcdir)/src/cmd/em_cmd_topo_sync.cpp \
     $(top_srcdir)/src/cmd/em_cmd_beacon_report.cpp \
     $(top_srcdir)/src/cmd/em_cmd_mld_reconfig.cpp \
     $(top_srcdir)/src/cmd/em_cmd_get_mld_config.cpp \
     $(top_srcdir)/src/ctrl/dm_easy_mesh_ctrl.cpp \
     $(top_srcdir)/src/ctrl/em_cmd_ctrl.cpp \
     $(top_srcdir)/src/ctrl/em_ctrl.cpp \
     $(top_srcdir)/src/ctrl/em_network_topo.cpp \
     $(top_srcdir)/src/ctrl/em_dev_test_ctrl.cpp \
     $(top_srcdir)/src/db/db_client.cpp \
     $(top_srcdir)/src/db/db_column.cpp \
     $(top_srcdir)/src/db/db_easy_mesh.cpp \
     $(top_srcdir)/src/dm/dm_ap_mld.cpp \
     $(top_srcdir)/src/dm/dm_cac_comp.cpp \
     $(top_srcdir)/src/dm/dm_easy_mesh.cpp \
     $(top_srcdir)/src/dm/dm_network.cpp \
     $(top_srcdir)/src/dm/dm_op_class.cpp \
     $(top_srcdir)/src/dm/dm_radio_cap.cpp \
     $(top_srcdir)/src/dm/dm_ssid_2_vid_map.cpp \
     $(top_srcdir)/src/dm/dm_bss.cpp \
     $(top_srcdir)/src/dm/dm_bss_list.cpp \
     $(top_srcdir)/src/dm/dm_bsta_mld.cpp \
     $(top_srcdir)/src/dm/dm_device.cpp \
     $(top_srcdir)/src/dm/dm_device_list.cpp \
     $(top_srcdir)/src/dm/dm_dpp.cpp \
     $(top_srcdir)/src/dm/dm_easy_mesh_list.cpp \
     $(top_srcdir)/src/dm/dm_ieee_1905_security.cpp \
     $(top_srcdir)/src/dm/dm_ieee_1905_security_list.cpp \
     $(top_srcdir)/src/dm/dm_network_list.cpp \
     $(top_srcdir)/src/dm/dm_network_ssid.cpp \
     $(top_srcdir)/src/dm/dm_network_ssid_list.cpp \
     $(top_srcdir)/src/dm/dm_op_class_list.cpp \
     $(top_srcdir)/src/dm/dm_policy.cpp \
     $(top_srcdir)/src/dm/dm_policy_list.cpp \
     $(top_srcdir)/src/dm/dm_radio_cap_list.cpp \
     $(top_srcdir)/src/dm/dm_radio.cpp \
     $(top_srcdir)/src/dm/dm_radio_list.cpp \
     $(top_srcdir)/src/dm/dm_sta.cpp \
     $(top_srcdir)/src/dm/dm_sta_list.cpp \
     $(top_srcdir)/src/dm/dm_tid_to_link.cpp \
     $(top_srcdir)/src/dm/dm_assoc_sta_mld.cpp \
     $(top_srcdir)/src/dm/dm_scan_result.cpp \
     $(top_srcdir)/src/dm/dm_scan_result_list.cpp \
     $(top_srcdir)/src/orch/em_orch.cpp  \
     $(top_srcdir)/src/orch/em_orch_ctrl.cpp \
     $(top_srcdir)/src/util_crypto/aes_siv.c \
     $(top_srcdir)/src/utils/util.cpp \
     $(top_srcdir)/OneWifi/source/utils/collection.c \
     $(top_srcdir)/OneWifi/lib/common/util.c \
     $(top_srcdir)/OneWifi/source/platform/rdkb/bus.c \ 
     $(top_srcdir)/OneWifi/source/platform/common/bus_common.c
 
 
onewifi_em_ctrl_LDFLAGS = -lm -lpthread -ldl -luuid -lcjson -lssl -lcrypto -lrbus -fsanitize=address -fsanitize=undefined -lmariadb

