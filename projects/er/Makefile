PREFIX = /usr/local
dbg = -g
# Makefile for the er "encrypt right" / "enoch root"

CC = gcc  # C compiler
CFLAGS = -fPIC -Wall -g  # C flags
RM = rm -f   # rm command

SRCS = er.c  # source files
OBJS = $(SRCS:.c=.o)

LDFLAGS = -lm -lenoch

er: $(OBJS)
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

.PHONY: clean
clean:
	rm -f $(OBJS) er

.PHONY: install
install: er
	mkdir -p $(PREFIX)/bin
	cp $< $(PREFIX)/bin/er

.PHONY: uninstall
uninstall:
	rm -f $(PREFIX)/bin/er
