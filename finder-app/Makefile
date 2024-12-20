CC := gcc
TARGET_WRITER := writer
OBJS := $(TARGET_WRITER).o
.PHONY: default all

all: default

default: $(TARGET_WRITER)

$(TARGET_WRITER): $(OBJS)
	$(CROSS_COMPILE)$(CC) *.o -o $(TARGET_WRITER)

$(TARGET_WRITER).o: $(TARGET_WRITER).c
	$(CROSS_COMPILE)$(CC) -c $(TARGET_WRITER).c

clean:
	rm -f $(TARGET_WRITER) *.o
