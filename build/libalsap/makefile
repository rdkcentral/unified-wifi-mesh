include ../makefile.inc


TARGET = $(AL_SAP_HOME)/libalsap.a
CPP = g++
CPPFLAGS = -I../../inc
AR = ar rcs

FILES := $(wildcard $(AL_SAP_HOME)/*.cpp)
OBJS := $(patsubst %.cpp, %.o, $(FILES))


ENABLE_DEBUG_MODE ?= OFF
ifeq ($(ENABLE_DEBUG_MODE),ON)
$(info ENABLE_DEBUG_MODE is set)
CPPFLAGS += "-DDEBUG_MODE"
endif



# Rule to build the target
$(TARGET): $(OBJS)
	$(AR) $(TARGET) $(OBJS)

# Rule to build object files
%.o: %.cpp
	$(CC) $(CPPFLAGS) -c $< -o $@

# Clean rule to remove generated files
.PHONY: clean
clean:
	rm -f $(TARGET) $(OBJS)

all:	$(TARGET)


install:	$(TARGET)
	cp $(TARGET) $(INSTALLDIR)/lib/
