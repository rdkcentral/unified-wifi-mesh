##########################################################################
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
lib_LTLIBRARIES=libalsap.la
 
libalsap_la_CPPFLAGS = \
    -I$(top_srcdir)/inc 
 
libalsap_la_CPPFLAGS += -g -fPIC
 
libalsap_la_SOURCES = \
 $(top_srcdir)/src/al-sap/al_service_access_point.cpp \
 $(top_srcdir)/src/al-sap/al_service_exception.cpp \
 $(top_srcdir)/src/al-sap/al_service_registration_response.cpp \
 $(top_srcdir)/src/al-sap/al_service_data_unit.cpp \
 $(top_srcdir)/src/al-sap/al_service_registration_request.cpp \
 $(top_srcdir)/src/al-sap/al_service_utils.cpp
