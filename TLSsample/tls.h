#ifndef TLS_H
#define TLS_H

#include <openssl/ssl.h>
#include <openssl/err.h>

//#define TLS_SERVER_PORT 4433
#define TLS_SERVER_PORT 30004

#define USE_LOCALHOST_CERT 0

#if USE_LOCALHOST_CERT
#define TLS_SERVER_IP   "127.0.0.1"
#define SERVER_CERT_FILE    "lgess2025s4localhostcert.pem"
#define SERVER_KEY_FILE     "lgess2025s4localhostkey.pem"
#define FSERVER_CERT_FILE    "lgess2025s4rpicert.pem"
#define FSERVER_KEY_FILE     "lgess2025s4rpikey.pem"
#else
#define TLS_SERVER_IP   "192.168.43.3"
#define SERVER_CERT_FILE    "lgess2025s4rpicert.pem"
#define SERVER_KEY_FILE     "lgess2025s4rpikey.pem"
#endif

#define CLIENT_CERT_FILE    "lgess2025s4clientcert.pem"
#define CLIENT_KEY_FILE     "lgess2025s4clientkey.pem"

#define FCLIENT_CERT_FILE    "lgess2025s4rpicert.pem"
#define FCLIENT_KEY_FILE     "lgess2025s4rpikey.pem"

SSL_CTX * myInitSSL(void);
int myFreeSSL(SSL_CTX *ctx, SSL *ssl);
int myAcceptSSL(SSL_CTX *ctx, int client_sock, SSL **ppSsl);

#endif // TLS_H

/**************************************************
openssl req -x509 -newkey rsa:2048 -keyout lgess2025s4localhostkey.pem -out lgess2025s4localhostcert.pem -days 365 -nodes \
-subj "/C=KR/ST=Seoul/L=Seoul/O=LG/OU=Security4/CN=localhost/emailAddress=jhoon.lee@lge.com"
openssl req -x509 -newkey rsa:2048 -keyout lgess2025s4rpikey.pem -out lgess2025s4rpicert.pem -days 365 -nodes \
-subj "/C=KR/ST=Seoul/L=Seoul/O=LG/OU=Security4/CN=192.168.43.3/emailAddress=jhoon.lee@lge.com"
openssl req -x509 -newkey rsa:2048 -keyout lgess2025s4clientkey.pem -out lgess2025s4clientcert.pem -days 365 -nodes \
-subj "/C=KR/ST=Seoul/L=Seoul/O=LG/OU=Security4/CN=Jaehoon Lee/emailAddress=jhoon.lee@lge.com"
**************************************************/
