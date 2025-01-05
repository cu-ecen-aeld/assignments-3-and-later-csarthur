CC ?= $(CROSS_COMPILE)gcc
CFLAGS ?= -c -g -Wall -Werror
LDFLAGS ?= -lpthread -lrt
TARGET_AESDSOCKET := aesdsocket
OBJS := $(TARGET_AESDSOCKET).o
.PHONY: default all

all: default

default: $(TARGET_AESDSOCKET)

$(TARGET_AESDSOCKET): $(OBJS)
	$(CC) $(FLAGS) $^ -o $@ $(INCLUDES) $(LDFLAGS)

$(TARGET_AESDSOCKET).o: $(TARGET_AESDSOCKET).c
	$(CC) $(CFLAGS) $(TARGET_AESDSOCKET).c

clean:
	rm -f $(TARGET_AESDSOCKET) *.o
