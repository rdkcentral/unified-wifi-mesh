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


PROGRAM = $(INSTALLDIR)/bin/onewifi_em_ctrl

INCLUDEDIRS = \
	-I$(ONEWIFI_EM_HOME)/inc \
	-I$(ONEWIFI_HAL_INTF_HOME)/ \
	-I$(ONEWIFI_HOME)/source/utils \
	-I$(ONEWIFI_HOME)/include \
   	-I$(RBUS_HOME)/include \
   	-I$(ONEWIFI_EM_HOME)/src/util_crypto \
	-I$(ONEWIFI_HOME)/lib/log \
	-I$(ONEWIFI_HOME)/lib/ds \
	-I$(ONEWIFI_HOME)/source/platform/linux \
	-I$(ONEWIFI_HOME)/source/platform/common \
	-I$(ONEWIFI_HOME)/source/platform/linux/he_bus/inc \
	-I$(ONEWIFI_HOME)/source/ccsp \
	-I$(STAGING_DIR)/usr/include \
	-I$(STAGING_DIR)/usr/include/mysql \

ifeq ($(WITH_SAP), 1)
INCLUDEDIRS += -I$(AL_SAP_HOME)/include
endif

ifneq ($(OS), Darwin)
CFLAGS += -DPLATFORM_LINUX
else
CFLAGS += -DPLATFORM_OSX
endif

CXXFLAGS += $(INCLUDEDIRS) -g -DUNIT_TEST -Wall -Wextra -Wpointer-arith -Wcast-qual -Wcast-align -Wstrict-aliasing -fno-common -Wctor-dtor-privacy -Wold-style-cast -Woverloaded-virtual -Wsign-promo -Wstrict-null-sentinel -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -pie -ftrapv -Wformat=2 -Wformat-security -Wuninitialized -Winit-self -Wconversion -Wsign-conversion -Wno-unused-parameter -std=c++17 #-Werror -O2 -Weffc++
CFLAGS += -DOPENWRT_BUILD
CXXFLAGS += -DOPENWRT_BUILD
ifeq ($(WITH_SAP), 1)
CXXFLAGS += -DAL_SAP
endif

ifdef TESTING
CXXFLAGS += -DTESTING
endif

LDFLAGS += $(LIBDIRS) $(LIBS)
#LDFLAGS += $(LIBDIRS) $(LIBS) -fsanitize=address -fsanitize=undefined

LIBDIRS = \
	-L$(INSTALLDIR)/lib \
	-L$(ONEWIFI_HOME)/install/lib/ \
	-L/usr/local/lib    \
	-L/usr/local/ssl/lib/ \
	-L$(STAGING_DIR)/usr/lib \

ifeq ($(WITH_SAP), 1)
LIBDIRS += -L$(AL_SAP_HOME)/build/lib
endif

ifneq ($(OS), Darwin)
LIBDIRS += -L$(INSTALLDIR)/lib/platform/x86-64
else
LIBDIRS += -L$(INSTALLDIR)/lib/platform/darwin
endif

LIBS = -lm -pthread -ldl -luuid -lcjson -lssl -lcrypto -lhebus -lmariadb

ifeq ($(WITH_SAP), 1)
LIBS += -lalsap
endif

GENERIC_SOURCES = $(ONEWIFI_HOME)/source/utils/collection.c \
	$(ONEWIFI_EM_SRC)/util_crypto/aes_siv.c \
	$(ONEWIFI_HOME)/lib/common/util.c \
    $(ONEWIFI_HOME)/source/platform/linux/bus.c \


CTRL_SOURCES = $(wildcard $(ONEWIFI_EM_SRC)/em/*.cpp) \
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
	$(wildcard $(ONEWIFI_EM_SRC)/cmd/*.cpp) \
	$(wildcard $(ONEWIFI_EM_SRC)/ctrl/*.cpp) \
	$(wildcard $(ONEWIFI_EM_SRC)/db/*.cpp) \
	$(wildcard $(ONEWIFI_EM_SRC)/dm/*.cpp) \
	$(ONEWIFI_EM_SRC)/orch/em_orch.cpp \
	$(ONEWIFI_EM_SRC)/orch/em_orch_ctrl.cpp \
	$(ONEWIFI_EM_SRC)/utils/util.cpp \

CTRL_OBJECTS = $(CTRL_SOURCES:.cpp=.o)
GENERIC_OBJECTS = $(GENERIC_SOURCES:.c=.o) 
ALLOBJECTS = $(CTRL_OBJECTS) $(GENERIC_OBJECTS)

all: $(PROGRAM)

$(PROGRAM): $(ALLOBJECTS)
	$(CXX) -o $@ $(ALLOBJECTS) $(LDFLAGS)

$(GENERIC_OBJECTS): %.o: %.c
	$(CC) $(CXXFLAGS) -o $@ -c $<

$(CTRL_OBJECTS): %.o: %.cpp
	$(CXX) $(CXXFLAGS) -o $@ -c $<

# Clean everything
clean:
	$(RM) $(ALLOBJECTS) $(PROGRAM)
	$(MAKE) clean_tests


# Google Test integration
TEST_DIR = $(ONEWIFI_EM_HOME)/tests
TEST_EXEC = $(INSTALLDIR)/bin/onewifi_em_test
TEST_SOURCES = $(wildcard $(TEST_DIR)/*.cpp)
TEST_OBJECTS = $(TEST_SOURCES:.cpp=.o)
TEST_CXXFLAGS = $(CXXFLAGS) -I/usr/include -I/usr/local/include -DTESTING

# Test target
test: check_test_files install_gtest $(TEST_OBJECTS)
	@$(MAKE) $(ALLOBJECTS) TESTING=1
	@echo "Building test executable with same link order as main build..."
	$(CXX) -o $(TEST_EXEC) $(TEST_OBJECTS) $(ALLOBJECTS) $(LIBDIRS) $(LIBS) -lgtest -lgtest_main -pthread -fsanitize=address -fsanitize=undefined
	@echo "Running tests..."
	@$(TEST_EXEC)

# Compile test source files
$(TEST_DIR)/%.o: $(TEST_DIR)/%.cpp
	@echo "Compiling test file $<..."
	$(CXX) $(TEST_CXXFLAGS) -o $@ -c $<

# Check if any test files exist
check_test_files:
	@if [ -z "$(TEST_SOURCES)" ]; then \
		echo "Error: No test files found in $(TEST_DIR)/"; \
		exit 1; \
	fi

# Install GTest if needed
install_gtest:
	@echo "Checking and installing Google Test if needed..."
	@chmod +x $(ONEWIFI_EM_HOME)/build/install-gtest.sh
	@$(ONEWIFI_EM_HOME)/build/install-gtest.sh

# Run the program
run:
	./$(PROGRAM)

# Clean test files only
clean_tests:
	$(RM) $(TEST_OBJECTS) $(TEST_EXEC)

.PHONY: all test install_gtest check_test_files clean_tests compile_test_objects clean run
