# Define the private extension include directory path
UWM_PRIVATE_EXT_INC_DIR = $(ONEWIFI_EM_HOME)/uwm-private-ext/inc

# Add the include path to CXXFLAGS (for C++ .cpp files) and CFLAGS
CXXFLAGS += -I$(UWM_PRIVATE_EXT_INC_DIR)
CFLAGS   += -I$(UWM_PRIVATE_EXT_INC_DIR)

# (Optional) If using standard local Make variables instead of OpenWrt build targets:
# INCLUDES += -I$(UWM_PRIVATE_EXT_INC_DIR)

# Listed explicitly rather than via $(wildcard): Automake parses _SOURCES
# statically when generating Makefile.in and can't see wildcard results,
# so new files here must also be added to these lists by hand.
UWM_PRIVATE_EXT_COMMON_SOURCES = \
    $(ONEWIFI_EM_HOME)/uwm-private-ext/src/common/lq_socket.cpp \
    $(ONEWIFI_EM_HOME)/uwm-private-ext/src/common/lq_listener.cpp \
    $(ONEWIFI_EM_HOME)/uwm-private-ext/src/common/em_vendor_ext.cpp

UWM_PRIVATE_EXT_AGENT_SOURCES = \
    $(UWM_PRIVATE_EXT_COMMON_SOURCES) \
    $(ONEWIFI_EM_HOME)/uwm-private-ext/src/agent/lq_agent_listener.cpp

UWM_PRIVATE_EXT_CTRL_SOURCES = \
    $(UWM_PRIVATE_EXT_COMMON_SOURCES) \
    $(ONEWIFI_EM_HOME)/uwm-private-ext/src/ctrl/vendor_subscription.cpp
