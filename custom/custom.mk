# Define the custom include directory path
CUSTOM_INC_DIR = $(ONEWIFI_EM_HOME)/custom/inc

# Add the include path to CXXFLAGS (for C++ .cpp files) and CFLAGS
CXXFLAGS += -I$(CUSTOM_INC_DIR)
CFLAGS   += -I$(CUSTOM_INC_DIR)

# (Optional) If using standard local Make variables instead of OpenWrt build targets:
# INCLUDES += -I$(CUSTOM_INC_DIR)

CUSTOM_AGENT_SOURCES = \
    $(wildcard $(ONEWIFI_EM_HOME)/custom/src/common/*.cpp) \
    $(wildcard $(ONEWIFI_EM_HOME)/custom/src/agent/*.cpp)

CUSTOM_CTRL_SOURCES = \
    $(wildcard $(ONEWIFI_EM_HOME)/custom/src/common/*.cpp) \
    $(wildcard $(ONEWIFI_EM_HOME)/custom/src/ctrl/*.cpp)