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

PROGRAM = $(INSTALLDIR)/bin/onewifi_em_cli
EM_CLI_LIBRARY = $(INSTALLDIR)/lib/libemcli.so

INCLUDEDIRS = \
	-I$(ONEWIFI_EM_HOME)/inc \
	-I$(ONEWIFI_EM_HOME)/src/utils \
	-I$(ONEWIFI_EM_HOME)/src/util/ \
	-I$(ONEWIFI_EM_HOME)/src/util_crypto/ \
	-I$(ONEWIFI_HAL_INTF_HOME) \
	-I$(ONEWIFI_HOME)/source/utils \
	-I$(ONEWIFI_HOME)/include \
	-I$(ONEWIFI_HOME)/source/platform/linux \
	-I$(ONEWIFI_HOME)/source/platform/common \
    -I$(ONEWIFI_HOME)/source/platform/linux/he_bus/inc \
	-I$(ONEWIFI_HOME)/source/ccsp \
    -I$(RBUS_HOME)/include \
	-I$(WIFI_CJSON) \


CXXFLAGS = $(INCLUDEDIRS) -g -std=c++17 -fPIC -I$(STAGING_DIR)/usr/include
CFLAGS = $(INCLUDEDIRS) -g
LDFLAGS = $(LIBDIRS) $(LIBS)
LIBDIRS = \
	-L$(INSTALLDIR)/lib \

LIBS = -lemcli -luuid -lm -lpthread -ldl -lcjson -lreadline -lssl -lcrypto -I$(STAGING_DIR)/usr/lib -lmariadb

GENERIC_SOURCES = $(ONEWIFI_HOME)/source/utils/collection.c	\
                  $(ONEWIFI_EM_SRC)/util_crypto/aes_siv.c \

CLI_SOURCES = $(wildcard $(ONEWIFI_EM_SRC)/cli/*.cpp) \
	$(wildcard $(ONEWIFI_EM_SRC)/cmd/*.cpp) \
    $(wildcard $(ONEWIFI_EM_SRC)/em/crypto/*.cpp) \
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
    $(ONEWIFI_EM_SRC)/em/em_net_node.cpp \
    $(ONEWIFI_EM_SRC)/utils/util.cpp \
    $(ONEWIFI_EM_SRC)/em/prov/easyconnect/ec_util.cpp \


MAIN_SOURCE = $(ONEWIFI_EM_SRC)/cli/main.c

CLI_OBJECTS = $(CLI_SOURCES:.cpp=.o)
GENERIC_OBJECTS = $(GENERIC_SOURCES:.c=.o) 
EMCLIOBJECTS = $(CLI_OBJECTS) $(GENERIC_OBJECTS)
MAIN_OBJECT = $(MAIN_SOURCE:.c=.o) 

all: $(EM_CLI_LIBRARY) $(PROGRAM)

$(EM_CLI_LIBRARY): $(EMCLIOBJECTS)
	$(CXX) -shared -o $@ $(EMCLIOBJECTS) $(LDFLAGS)

$(GENERIC_OBJECTS): %.o: %.c
	$(CC) $(CXXFLAGS) -o $@ -c $<

$(CLI_OBJECTS): %.o: %.cpp
	$(CXX) $(CXXFLAGS) -o $@ -c $<

$(MAIN_OBJECT): %.o: %.c
	$(CXX) $(CFLAGS) -o $@ -c $<

$(PROGRAM):
# use go 1.19 or above to build
ifeq ($(CC), aarch64-linux-gnu-gcc-11)
	CGO_ENABLED=1 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w -extldflags '-L$(INSTALLDIR)/lib -lcrypto -lssl -luuid'" -o $(PROGRAM) $(ONEWIFI_EM_SRC)/cli/*.go
else
	go build -ldflags="-extldflags '-L$(INSTALLDIR)/lib -lcrypto -lssl -luuid'" -o $(PROGRAM) $(ONEWIFI_EM_SRC)/cli/*.go
endif

# Clean target: "make -f Makefile.Linux clean" to remove unwanted objects and executables.
#

clean:
	$(RM) $(MAIN_OBJECT) $(EMCLIOBJECTS) $(EM_CLI_LIBRARY) $(PROGRAM) $(PROGRAM)

#
# Run target: "make -f Makefile.Linux run" to execute the application
#             You will need to add $(RUNARGS) for any command line parameters
#             that you defined earlier in this file.
# 

run:
	@cd $(INSTALLDIR)/bin && \
	LD_LIBRARY_PATH=$(INSTALLDIR)/lib ./onewifi_em_cli $(RUNARGS)

.PHONY: run
