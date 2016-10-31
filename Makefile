sinclude config.mk

V = 0.1

CC                   ?= cc
LD                   := ${CC}
CFLAGS               ?= -O2 -pipe -Wall -Wextra
CFLAGS               += -std=c99 -pedantic -DVERSION=\"$V\"
INSTALL_MAN          ?= install -c -m 644
INSTALL_PROGRAM      ?= install -c -m 755
PREFIX               ?= /usr/local
BINDIR               ?= ${PREFIX}/bin
MANDIR               ?= ${PREFIX}/man

OBJs =	icb.o

all: icb

install: icb icb.1
	install -D -m 0755 icb ${BINDIR}/icb
	install -D -m 0644 icb.1 ${MANDIR}/man1/icb.1

.c.o:
	${CC} ${CFLAGS} -c -o $@ $<

.o:
	${LD} -o $@ ${LDFLAGS} ${.ALLSRC} ${LIBS}

clean:
	rm -rf ${OBJs} icb icb.core

icb.o: icb.c
icb: icb.o

.PHONY: all clean
