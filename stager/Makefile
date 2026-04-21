include ../config.mk

CC     := $(CC_CROSS)
CFLAGS := -Wall -Wextra -static

all: stager

stager: stager.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f stager

.PHONY: all clean
