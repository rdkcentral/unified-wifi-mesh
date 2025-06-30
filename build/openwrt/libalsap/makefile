include ../makefile.inc

AL_SAP_LIB = $(INSTALLDIR)/lib/libalsap.a
CXXFLAGS = -I$(ONEWIFI_EM_HOME)/inc

TRANSMITTER_SRC = $(AL_SAP_HOME)/test_libalsap_transmitter.cpp
RECEIVER_SRC = $(AL_SAP_HOME)/test_libalsap_receiver.cpp
TRANSMITTER = $(INSTALLDIR)/bin/test_alsap_transmitter
RECEIVER = $(INSTALLDIR)/bin/test_alsap_receiver

ALL_CPP_FILES = $(wildcard $(AL_SAP_HOME)/*.cpp)
EXCLUDE_FILES = $(TRANSMITTER_SRC) $(RECEIVER_SRC)
LIB_FILES = $(filter-out $(EXCLUDE_FILES), $(ALL_CPP_FILES))
LIB_OBJS = $(LIB_FILES:.cpp=.o)

ifeq ($(WITH_SAP), 1)
CXXFLAGS += -DAL_SAP
LIBS = -lalsap
endif

ifeq ($(ENABLE_DEBUG_MODE),ON)
$(info ENABLE_DEBUG_MODE is set)
CXXFLAGS += -DDEBUG_MODE
endif

# Default target
all: $(AL_SAP_LIB) $(TRANSMITTER) $(RECEIVER)

# Rule to build the static library
$(AL_SAP_LIB): $(LIB_OBJS)
	$(AR) -rcs $@ $^

# Rule to build object files for library
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -o $@ -c $<

# Rules to build binaries
$(TRANSMITTER): $(TRANSMITTER_SRC)
	$(CXX) $(CXXFLAGS) $< -o $@ -L$(INSTALLDIR)/lib $(LIBS)

$(RECEIVER): $(RECEIVER_SRC)
	$(CXX) $(CXXFLAGS) $< -o $@ -L$(INSTALLDIR)/lib $(LIBS)

# Clean rule
.PHONY: clean
clean:
	rm -f $(AL_SAP_LIB) $(LIB_OBJS) $(TRANSMITTER) $(RECEIVER)

