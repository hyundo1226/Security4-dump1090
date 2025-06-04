CFLAGS?=-O2 -g -Wall -W $(shell pkg-config --cflags librtlsdr)
LDLIBS+=$(shell pkg-config --libs librtlsdr) -lpthread -lm
#LG_SECURITY_ENHANCEMENT
LDLIBS+=-lssl -lcrypto
CC?=gcc
PROGNAME=dump1090

all: dump1090

%.o: %.c
	$(CC) $(CFLAGS) -c $<

dump1090: dump1090.o anet.o tserver.o
	$(CC) -g -o dump1090 dump1090.o anet.o tserver.o $(LDFLAGS) $(LDLIBS)

tserver.o: TLSsample/tserver.c TLSsample/tls.h
	$(CC) $(CFLAGS) -c $<

dump1090.o: TLSsample/tls.h

clean:
	rm -f *.o dump1090
