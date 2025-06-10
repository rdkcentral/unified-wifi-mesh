##########################################################################
 # Copyright 2023 Comcast Cable Communications Management, LLC
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
 #
 # SPDX-License-Identifier: Apache-2.0
##########################################################################

include ../makefile.inc

#
# program
#

PROGRAM = $(INSTALLDIR)/bin/onewifi_em_agent

INCLUDEDIRS = \
	-I$(ONEWIFI_EM_HOME)/inc \
	-I$(ONEWIFI_EM_HOME)/src/utils \
	-I$(ONEWIFI_HAL_INTF_HOME) \
	-I$(ONEWIFI_HOME)/source/utils \
	-I$(ONEWIFI_HOME)/include \
    	-I$(ONEWIFI_BUS_LIB_HOME)/inc \
    	-I$(ONEWIFI_HOME)/lib/log \
    	-I$(ONEWIFI_HOME)/lib/ds \
    	-I$(ONEWIFI_HOME)/source/platform/linux \
    	-I$(ONEWIFI_HOME)/source/platform/common \
    	-I$(ONEWIFI_HOME)/source/platform/linux/he_bus/inc \
        -I$(ONEWIFI_EM_HOME)/src/util_crypto \
        -I$(ONEWIFI_HOME)/source/ccsp
ifeq ($(WITH_SAP), 1)
INCLUDEDIRS += -I$(AL_SAP_HOME)/include
endif

$(info The value of VARIABLE is $(ONEWIFI_HAL_INTF_HOME))
CXX_COMMON_FLAGS = -DUNIT_TEST -DEASY_MESH_NODE -DEM_APP -Wall -Wextra -Wpointer-arith -Wcast-qual -Wcast-align -Wstrict-aliasing -fno-common -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -pie -ftrapv -Wformat=2 -Wformat-security -Wuninitialized -Winit-self -Wconversion -Wsign-conversion -Wno-unused-parameter -fsanitize=address -fsanitize=undefined #-Werror -O2 -Weffc++
CXX_SPECIFIC_FLAGS = -Wctor-dtor-privacy -Wold-style-cast -Woverloaded-virtual -Wsign-promo -Wstrict-null-sentinel -std=c++17

ifeq ($(WITH_SAP), 1)
CXX_COMMON_FLAGS += -DAL_SAP
endif

CXXFLAGS += $(INCLUDEDIRS) -g $(CXX_COMMON_FLAGS) $(CXX_SPECIFIC_FLAGS)
CFLAGS += $(INCLUDEDIRS) -g $(CXX_COMMON_FLAGS)

LDFLAGS += $(LIBDIRS) $(LIBS) -fsanitize=address -fsanitize=undefined -lmariadb -L$(STAGING_DIR)/usr/lib

LIBDIRS = \
	-L$(INSTALLDIR)/lib \
    -L$(ONEWIFI_HOME)/install/lib/
ifeq ($(WITH_SAP), 1)
LIBDIRS += -L$(AL_SAP_HOME)/
endif

LIBS = -lm -lpthread -ldl -lcjson -luuid -lssl -lcrypto -lwebconfig -lhebus -lmariadb
ifeq ($(WITH_SAP), 1)
LIBS += -lalsap
endif

GENERIC_SOURCES = $(ONEWIFI_HOME)/source/utils/collection.c \
    $(ONEWIFI_EM_SRC)/util_crypto/aes_siv.c \
    $(ONEWIFI_HOME)/lib/common/util.c \
    $(ONEWIFI_HOME)/source/platform/linux/bus.c \

AGENT_SOURCES = $(wildcard $(ONEWIFI_EM_SRC)/em/*.cpp) \
	$(wildcard $(ONEWIFI_EM_SRC)/em/config/*.cpp) \
	$(wildcard $(ONEWIFI_EM_SRC)/em/prov/*.cpp) \
	$(wildcard $(ONEWIFI_EM_SRC)/em/prov/easyconnect/*.cpp) \
	$(wildcard $(ONEWIFI_EM_SRC)/em/disc/*.cpp) \
	$(wildcard $(ONEWIFI_EM_SRC)/em/channel/*.cpp) \
	$(wildcard $(ONEWIFI_EM_SRC)/em/capability/*.cpp) \
	$(wildcard $(ONEWIFI_EM_SRC)/em/metrics/*.cpp) \
	$(wildcard $(ONEWIFI_EM_SRC)/em/steering/*.cpp) \
	$(wildcard $(ONEWIFI_EM_SRC)/em/policy_cfg/*.cpp) \
	$(wildcard $(ONEWIFI_EM_SRC)/em/crypto/*.cpp) \
    	$(ONEWIFI_EM_SRC)/orch/em_orch.cpp \
    	$(ONEWIFI_EM_SRC)/orch/em_orch_agent.cpp \
	$(wildcard $(ONEWIFI_EM_SRC)/cmd/*.cpp) \
	$(wildcard $(ONEWIFI_EM_SRC)/agent/*.cpp) \
	$(ONEWIFI_EM_SRC)/dm/dm_device.cpp \
	$(ONEWIFI_EM_SRC)/dm/dm_ieee_1905_security.cpp \
	$(ONEWIFI_EM_SRC)/dm/dm_easy_mesh.cpp \
	$(ONEWIFI_EM_SRC)/dm/dm_radio.cpp \
	$(ONEWIFI_EM_SRC)/dm/dm_bss.cpp \
	$(ONEWIFI_EM_SRC)/dm/dm_dpp.cpp \
	$(ONEWIFI_EM_SRC)/dm/dm_network_ssid.cpp \
	$(ONEWIFI_EM_SRC)/dm/dm_network.cpp \
	$(ONEWIFI_EM_SRC)/dm/dm_op_class.cpp \
	$(ONEWIFI_EM_SRC)/dm/dm_policy.cpp \
	$(ONEWIFI_EM_SRC)/dm/dm_scan_result.cpp \
	$(ONEWIFI_EM_SRC)/dm/dm_sta.cpp \
	$(ONEWIFI_EM_SRC)/dm/dm_radio_cap.cpp \
    $(ONEWIFI_EM_SRC)/dm/dm_cac_comp.cpp \
    $(ONEWIFI_EM_SRC)/dm/dm_ap_mld.cpp \
    $(ONEWIFI_EM_SRC)/dm/dm_bsta_mld.cpp \
    $(ONEWIFI_EM_SRC)/dm/dm_assoc_sta_mld.cpp \
    $(ONEWIFI_EM_SRC)/dm/dm_tid_to_link.cpp \
    $(ONEWIFI_EM_SRC)/utils/util.cpp \

AGENT_OBJECTS = $(AGENT_SOURCES:.cpp=.o)
GENERIC_OBJECTS = $(GENERIC_SOURCES:.c=.o) 
ALLOBJECTS = $(AGENT_OBJECTS) $(GENERIC_OBJECTS)

all: $(BUS_LIBRARY) $(PROGRAM)

$(PROGRAM): $(ALLOBJECTS)
	$(CXX) -o $@ $(ALLOBJECTS) $(LDFLAGS)

$(GENERIC_OBJECTS): %.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

$(AGENT_OBJECTS): %.o: %.cpp
	$(CXX) $(CXXFLAGS) -o $@ -c $<

# Clean target: "make -f Makefile.Linux clean" to remove unwanted objects and executables.
#

clean:
	$(RM) $(ALLOBJECTS) $(PROGRAM)

#
# Run target: "make -f Makefile.Linux run" to execute the application
#             You will need to add $(VARIABLE_NAME) for any command line parameters 
#             that you defined earlier in this file.
# 

run:
	./$(PROGRAM) 

