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

include ./makefile.inc

#
# program
#

PROGRAM = $(INSTALLDIR)/bin/optimizer_cloud_sim

INCLUDEDIRS = \
        -I$(OPTIMIZER_SRC) \
        -I$(OPTIMIZER_SRC)/tests/cloud_sim \
        -I$(OPTIMIZER_SRC)/tests/cloud_sim/web \
        -I$(OPTIMIZER_SRC)/test \
        -I$(ONEWIFI_EM_HOME)/inc \
        -I$(ONEWIFI_EM_HOME)/src/utils \
        -I$(ONEWIFI_EM_HOME)/../OneWifi/source/utils \
        -I$(ONEWIFI_EM_HOME)/../OneWifi/include \
        -I$(ONEWIFI_EM_HOME)/../halinterface/include \
        -I$(ONEWIFI_BUS_LIB_HOME)/inc \
        -I$(ONEWIFI_EM_HOME)/../OneWifi/lib/log \
        -I$(ONEWIFI_EM_HOME)/../OneWifi/lib/ds \
        -I$(ONEWIFI_EM_HOME)/../OneWifi/source/platform/linux \
        -I$(ONEWIFI_EM_HOME)/../OneWifi/source/platform/common \
        -I$(ONEWIFI_EM_HOME)/../OneWifi/source/platform/linux/he_bus/inc \
        -I$(ONEWIFI_EM_HOME)/src/util_crypto \
        -I$(ONEWIFI_EM_HOME)/../OneWifi/source/ccsp \
        -I$(RBUS_HOME)/include/rbus \
        -I$(PARODUS_DIR)/include/libparodus \
        -I$(PARODUS_DIR)/include

ifeq ($(WITH_SAP), 1)
INCLUDEDIRS += -I$(AL_SAP_HOME)/include
endif

CXXFLAGS += $(INCLUDEDIRS) -g -DEASY_MESH_NODE -DEM_APP -Wall -Wextra -Wpointer-arith -Wcast-qual -Wcast-align -Wstrict-aliasing -fno-common -Wctor-dtor-privacy -Wold-style-cast -Woverloaded-virtual -Wsign-promo -Wstrict-null-sentinel -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -pie -ftrapv -Wformat=2 -Wformat-security -Wuninitialized -Winit-self -Wconversion -Wsign-conversion -Weffc++ -Wno-unused-parameter -std=c++17 -fsanitize=address -fsanitize=undefined #-Werror -O2
ifeq ($(WITH_SAP), 1)
CXXFLAGS += -DAL_SAP
endif
LDFLAGS += $(LIBDIRS) -Wl,-rpath,$(PARODUS_DIR)/lib $(LIBS) -fsanitize=address -fsanitize=undefined

LIBDIRS = \
    -L$(INSTALLDIR)/lib \
    -L$(ONEWIFI_EM_HOME)/../OneWifi/install/lib \
    -L$(RBUS_HOME)/lib \
    -L$(PARODUS_DIR)/lib

ifeq ($(WITH_SAP), 1)
LIBDIRS += -L$(AL_SAP_HOME)/
endif

LIBS = -lm -lpthread -ldl -lcjson -luuid -lssl -lcrypto -lwebconfig -lhebus -lrbus -lwrp-c -lmsgpackc -ltrower-base64 -lcimplog -lcurl
ifeq ($(WITH_SAP), 1)
LIBS += -lalsap
endif

GENERIC_SOURCES = $(ONEWIFI_EM_HOME)/../OneWifi/source/utils/collection.c \
    $(ONEWIFI_EM_SRC)/util_crypto/aes_siv.c \
    $(ONEWIFI_EM_HOME)/../OneWifi/lib/common/util.c \
    $(ONEWIFI_EM_HOME)/../OneWifi/source/platform/linux/bus.c

SOURCES = $(wildcard $(OPTIMIZER_SRC)/tests/cloud_sim/*.cpp) \
                $(wildcard $(OPTIMIZER_SRC)/tests/cloud_sim/web/*.cpp) \
                $(OPTIMIZER_SRC)/optimizer_event.cpp \

OBJECTS = $(SOURCES:.cpp=.o)
GENERIC_OBJECTS = $(GENERIC_SOURCES:.c=.o) 
ALLOBJECTS = $(OBJECTS) $(GENERIC_OBJECTS)

all: $(BUS_LIBRARY) $(PROGRAM)

.PHONY: test-scan-web
test-scan-web:
	$(CXX) $(CXXFLAGS) $(OPTIMIZER_SRC)/tests/cloud_sim/tests/scan_web_test.cpp \
		$(OPTIMIZER_SRC)/tests/cloud_sim/web/web.cpp $(OPTIMIZER_SRC)/optimizer_event.cpp \
		-o $(INSTALLDIR)/bin/optimizer_scan_web_test -lcjson
	$(INSTALLDIR)/bin/optimizer_scan_web_test

$(PROGRAM): $(ALLOBJECTS)
	$(CXX) -o $@ $(ALLOBJECTS) $(LDFLAGS)

$(GENERIC_OBJECTS): %.o: %.c
	$(CC) $(CXXFLAGS) -o $@ -c $<

$(OBJECTS): %.o: %.cpp
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
