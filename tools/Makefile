# Makefile for capstone rootkit tools
#
# Builds mykill (extended C2)
#
# Usage:
#   make          — build all tools
#   make clean    — remove build artifacts


include ../config.mk

CC     := $(CC_CROSS)
CFLAGS := -Wall -Wextra -static

all: mykill

mykill: mykill.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f mykill

.PHONY: all clean
