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
bin_PROGRAMS = onewifi_em_network_optimser
 
onewifi_em_network_optimser_CPPFLAGS = \
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

onewifi_em_network_optimser_CXXFLAGS = $(INCLUDEDIRS) -g -DUNIT_TEST -Wall -Wextra -pedantic -Wpedantic -Wpointer-arith -Wcast-qual -Wcast-align -Wstrict-aliasing -fno-common -Wctor-dtor-privacy -Wold-style-cast -Woverloaded-virtual -Wsign-promo -Wstrict-null-sentinel -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -pie -ftrapv -Wformat=2 -Wformat-security -Wuninitialized -Winit-self -Wsign-conversion -Weffc++ -Wno-unused-parameter -std=c++17 -fsanitize=address -fsanitize=undefined #-Wconversion -Werror -O2

onewifi_em_network_optimser_SOURCES =  \
     $(top_srcdir)/src/network_optimiser/test_tr181.cpp \
     $(top_srcdir)/OneWifi/source/utils/collection.c \
     $(top_srcdir)/OneWifi/lib/common/util.c \
     $(top_srcdir)/OneWifi/source/platform/rdkb/bus.c \ 
     $(top_srcdir)/OneWifi/source/platform/common/bus_common.c
 
 
onewifi_em_network_optimser_LDFLAGS = -lm -lpthread -ldl -luuid -lcjson -lssl -lcrypto -lwifi_bus -lrbus #-lwifi_webconfig
onewifi_em_network_optimser_LDADD = $(top_builddir)/src/al-sap/libalsap.la

