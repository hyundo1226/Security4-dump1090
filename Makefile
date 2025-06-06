CFLAGS?=-O2 -g -Wall -W $(shell pkg-config --cflags librtlsdr)
LDLIBS+=$(shell pkg-config --libs librtlsdr) -lpthread -lm
#LG_SECURITY_ENHANCEMENT
LDLIBS+=-lssl -lcrypto
CC?=gcc
PROGNAME=dump1090

all: dump1090 sqlog_viewer

%.o: %.c
	$(CC) $(CFLAGS) -c $<

dump1090: dump1090.o anet.o tserver.o sqlog.o
	$(CC) -g -o dump1090 dump1090.o anet.o tserver.o sqlog.o $(LDFLAGS) $(LDLIBS)

tserver.o: TLSsample/tserver.c TLSsample/tls.h
	$(CC) $(CFLAGS) -c $<

dump1090.o: TLSsample/tls.h

sqlog_test_suite: sqlog_test sqlog_viewer

sqlog_test: sqlog_test.o sqlog.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LDLIBS)

sqlog.o: sqlog.c sqlog.h
	$(CC) $(CFLAGS) -c -o $@ $<

#sqlog_test.o: sqlog.c sqlog.h
#	$(CC) -DSQLOG_TEST $(CFLAGS) -c -o $@ $<

sqlog_viewer: sqlog_viewer.o sqlog.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LDLIBS)

sqlog_viewer.o: sqlog_viewer.c sqlog.h
	$(CC) $(CFLAGS) -c -o $@ $<

lgess2025s4rpilogkey:
	openssl rand -hex 32 > lgess2025s4rpilogkey.hex

distclean: clean
	rm -f dump1090 sqlog_test sqlog_viewer
clean:
	rm -f *.o *.log*
