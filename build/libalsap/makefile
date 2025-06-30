include ../makefile.inc

AL_SAP_LIB = $(AL_SAP_HOME)/libalsap.a
CPP = g++
CPPFLAGS = -I../../inc
AR = ar rcs

TRANSMITTER_SRC = $(AL_SAP_HOME)/test_libalsap_transmitter.cpp
RECEIVER_SRC = $(AL_SAP_HOME)/test_libalsap_receiver.cpp
TRANSMITTER = $(INSTALLDIR)/bin/test_alsap_transmitter
RECEIVER = $(INSTALLDIR)/bin/test_alsap_receiver

ALL_CPP_FILES = $(wildcard $(AL_SAP_HOME)/*.cpp)
EXCLUDE_FILES = $(TRANSMITTER_SRC) $(RECEIVER_SRC)
LIB_FILES = $(filter-out $(EXCLUDE_FILES), $(ALL_CPP_FILES))
LIB_OBJS = $(LIB_FILES:.cpp=.o)

ifeq ($(WITH_SAP), 1)
CPPFLAGS += -DAL_SAP
LIBS = -lalsap
endif

ifeq ($(ENABLE_DEBUG_MODE),ON)
$(info ENABLE_DEBUG_MODE is set)
CPPFLAGS += -DDEBUG_MODE
endif

# Default target
all: $(AL_SAP_LIB) $(TRANSMITTER) $(RECEIVER)

# Rule to build the static library
$(AL_SAP_LIB): $(LIB_OBJS)
	$(AR) $(AL_SAP_LIB) $(LIB_OBJS)

# Rule to build object files for library
%.o: %.cpp
	$(CPP) $(CPPFLAGS) -c $< -o $@

# Rules to build binaries
$(TRANSMITTER): $(TRANSMITTER_SRC) $(AL_SAP_LIB)
	$(CPP) $(CPPFLAGS) $< -o $@ -L$(AL_SAP_HOME) $(LIBS)

$(RECEIVER): $(RECEIVER_SRC) $(AL_SAP_LIB)
	$(CPP) $(CPPFLAGS) $< -o $@ -L$(AL_SAP_HOME) $(LIBS)

# Clean rule
.PHONY: clean
clean:
	rm -f $(AL_SAP_LIB) $(LIB_OBJS) $(TRANSMITTER) $(RECEIVER)

# Optional install
install: $(AL_SAP_LIB)
	cp $(AL_SAP_LIB) $(INSTALLDIR)/lib/
