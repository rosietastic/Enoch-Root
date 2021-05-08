PREFIX = /usr/local
dbg = -g
# Makefile for the libenoch dynamic shared library

CC = gcc  # C compiler
CFLAGS = -fPIC -Wall -Wextra -O2 -g  # C flags
LDFLAGS = -shared   # linking flags
RM = rm -f   # rm command
TARGET_LIB = libenoch.so  # target lib

SRCS = libenoch.c  # source files
OBJS = $(SRCS:.c=.o)

.PHONY: all
all: ${TARGET_LIB}

$(TARGET_LIB): $(OBJS)
	$(CC) ${LDFLAGS} -o $@ $^

$(SRCS:.c=.d):%.d:%.c
	$(CC) $(CFLAGS) -MM $< >$@

include $(SRCS:.c=.d)

.PHONY: clean
clean:
	-${RM} ${TARGET_LIB} ${OBJS} $(SRCS:.c=.d)

.PHONY: install
install: $(TARGET_LIB)
	mkdir -p $(PREFIX)/lib
	cp $(TARGET_LIB) $(PREFIX)/lib/$(TARGET_LIB)

.PHONY: uninstall
uninstall:
	rm -f $(PREFIX)/lib/$(TARGET_LIB)
