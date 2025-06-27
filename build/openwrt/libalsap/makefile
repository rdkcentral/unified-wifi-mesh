include ../makefile.inc

AL_SAP_LIB = $(INSTALLDIR)/lib/libalsap.a
CXXFLAGS = -I$(ONEWIFI_EM_HOME)/inc

LIB_FILES = $(wildcard $(AL_SAP_HOME)/*.cpp)
LIB_OBJS = $(LIB_FILES:.cpp=.o)

TRANSMITTER_SRC = $(AL_SAP_HOME)/../../tests/test_libalsap_transmitter.cpp
RECEIVER_SRC = $(AL_SAP_HOME)/../../tests/test_libalsap_receiver.cpp
TRANSMITTER = $(INSTALLDIR)/bin/test_alsap_transmitter
RECEIVER = $(INSTALLDIR)/bin/test_alsap_receeiver

ifeq ($(ENABLE_DEBUG_MODE),ON)
$(info ENABLE_DEBUG_MODE is set)
CPPFLAGS += -DDEBUG_MODE
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
	$(CXX) $(CXXFLAGS) $< -o $@ -L$(INSTALLDIR)/lib -lalsap

$(RECEIVER): $(RECEIVER_SRC)
	$(CXX) $(CXXFLAGS) $< -o $@ -L$(INSTALLDIR)/lib -lalsap

# Clean rule
.PHONY: clean
clean:
	rm -f $(AL_SAP_LIB) $(LIB_OBJS) $(TRANSMITTER) $(RECEIVER)

