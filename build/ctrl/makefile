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
	-I$(ONEWIFI_EM_HOME)/src/utils \
	-I$(ONEWIFI_HAL_INTF_HOME)/ \
	-I$(ONEWIFI_HOME)/source/utils \
	-I$(ONEWIFI_HOME)/include \
    	-I$(RBUS_HOME)/include \
    	-I$(ONEWIFI_EM_HOME)/src/util_crypto \
	-I$(WIFI_CJSON) \

CXXFLAGS = $(INCLUDEDIRS) -g -DUNIT_TEST
LDFLAGS = $(LIBDIRS) $(LIBS)
LIBDIRS = \
	-L$(INSTALLDIR)/lib \

LIBS = -lm -lpthread -ldl -luuid -lcjson -lssl -lcrypto -lmysqlcppconn

GENERIC_SOURCES = $(ONEWIFI_HOME)/source/utils/collection.c \
	$(ONEWIFI_EM_SRC)/util_crypto/aes_siv.c \

CTRL_SOURCES = $(wildcard $(ONEWIFI_EM_SRC)/em/*.cpp) \
    	$(wildcard $(ONEWIFI_EM_SRC)/em/config/*.cpp) \
    	$(wildcard $(ONEWIFI_EM_SRC)/em/prov/*.cpp) \
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

