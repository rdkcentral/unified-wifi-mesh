include ../makefile.inc

TARGET = $(AL_SAP_HOME)/libalsap.a
CPP = g++
CPPFLAGS = -I../../inc
AR = ar rcs

FILES := $(wildcard $(AL_SAP_HOME)/*.cpp)
OBJS := $(patsubst %.cpp, %.o, $(FILES))

TRANSMITTER_SRC = $(AL_SAP_HOME)/../../tests/test_libalsap_transmitter.cpp
RECEIVER_SRC = $(AL_SAP_HOME)/../../tests/test_libalsap_receiver.cpp
TRANSMITTER = $(INSTALLDIR)/bin/test_alsap_transmitter
RECEIVER = $(INSTALLDIR)/bin/test_alsap_receeiver

ifeq ($(ENABLE_DEBUG_MODE),ON)
$(info ENABLE_DEBUG_MODE is set)
CPPFLAGS += -DDEBUG_MODE
endif

# Default target
all: $(TARGET) $(TRANSMITTER) $(RECEIVER)

# Rule to build the static library
$(TARGET): $(OBJS)
	$(AR) $(TARGET) $(OBJS)

# Rule to build object files for library
%.o: %.cpp
	$(CPP) $(CPPFLAGS) -c $< -o $@

# Rules to build binaries
$(TRANSMITTER): $(TRANSMITTER_SRC) $(TARGET)
	$(CPP) $(CPPFLAGS) $< -o $@ -L$(AL_SAP_HOME) -lalsap

$(RECEIVER): $(RECEIVER_SRC) $(TARGET)
	$(CPP) $(CPPFLAGS) $< -o $@ -L$(AL_SAP_HOME) -lalsap

# Clean rule
.PHONY: clean
clean:
	rm -f $(TARGET) $(OBJS) $(TRANSMITTER) $(RECEIVER)

# Optional install
install: $(TARGET)
	cp $(TARGET) $(INSTALLDIR)/lib/