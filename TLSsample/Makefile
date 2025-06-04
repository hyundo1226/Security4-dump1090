CFLAGS=-O2 -g -Wall -W -DTLS_TEST
LDLIBS+=-lssl -lcrypto
CC=gcc

all: tserver tclient

clean: 
	rm -f tserver tclient tserver.o tclient.o

%.o: %.c
	$(CC) $(CFLAGS) -c $<

tserver: tserver.o tls.h
	gcc -o $@ $< $(LDFLAGS) $(LDLIBS)

tclient: tclient.o tls.h
	gcc -o $@ $< $(LDFLAGS) $(LDLIBS)

tserver.o: tserver.c tls.h

tclient.o: tclient.c tls.h

key:
	openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes

lgess2025s4:
	openssl req -x509 -newkey rsa:2048 -keyout lgess2025s4localhostkey.pem -out lgess2025s4localhostcert.pem -days 365 -nodes \
		-subj "/C=KR/ST=Seoul/L=Seoul/O=LG/OU=Security4/CN=localhost/emailAddress=jhoon.lee@lge.com"
	openssl req -x509 -newkey rsa:2048 -keyout lgess2025s4rpikey.pem -out lgess2025s4rpicert.pem -days 365 -nodes \
		-subj "/C=KR/ST=Seoul/L=Seoul/O=LG/OU=Security4/CN=192.168.43.3/emailAddress=jhoon.lee@lge.com"
	openssl req -x509 -newkey rsa:2048 -keyout lgess2025s4clientkey.pem -out lgess2025s4clientcert.pem -days 365 -nodes \
		-subj "/C=KR/ST=Seoul/L=Seoul/O=LG/OU=Security4/CN=Jaehoon Lee/emailAddress=jhoon.lee@lge.com"