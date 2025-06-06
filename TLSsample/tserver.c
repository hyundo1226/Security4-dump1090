#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "tls.h"
#include "../sqlog.h"

SSL_CTX *myInitSSL(void);
int myFreeSSL(SSL_CTX *ctx, SSL *ssl);
int myAcceptSSL(SSL_CTX *ctx, int client_sock, SSL **ppSsl);

SSL_CTX *
myInitSSL(void)
{
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx)
    {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // 서버 인증서와 개인키 로드
    if (SSL_CTX_use_certificate_file(ctx, SERVER_CERT_FILE, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY_FILE, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // 클라이언트 인증서 검증을 위한 CA 인증서 설정 (클라이언트 인증서 자체를 신뢰)
    if (!SSL_CTX_load_verify_locations(ctx, CLIENT_CERT_FILE, NULL))
    {
        fprintf(stderr, "Failed to load client CA cert\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    return ctx;
}

int myAcceptSSL(SSL_CTX *ctx, int client_sock, SSL **ppSsl)
{
    int iRet, iRetry = 10, iErr;
    *ppSsl = SSL_new(ctx);
    SSL_set_fd(*ppSsl, client_sock);


    printf("Performing SSL_accept... for client_socket[%d]\n", client_sock);
    while (iRetry > 0)
    {
        iRet = SSL_accept(*ppSsl);
        if (iRet <= 0)
        {
            iErr = SSL_get_error(*ppSsl, iRet);
            fprintf(stderr, "SSL_accept failed with return code %d, SSL_get_error: %d\n", iRet, iErr);
            ERR_print_errors_fp(stderr);
        }
        else
        {
            printf("succeeded\n");
            break;
        }
        usleep(100000);
        iRetry--;
        printf("retry %d left\n", iRetry);
    }

    return iRet;
}

#ifdef TLS_TEST
int main(int argc, char *argv[])
{
    int tls_server_port = TLS_SERVER_PORT;

    if (argc >= 2)
        tls_server_port = atoi(argv[1]);

    printf("tls server opens %d\n", tls_server_port);

    signal(SIGPIPE, SIG_IGN);

    SSL_CTX *ctx = myInitSSL();

    // TCP 서버 소켓 설정
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0)
    {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }
    printf("Socket created = %d\n", server_sock);

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(tls_server_port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("Bind failed");
        close(server_sock);
        exit(EXIT_FAILURE);
    }

    if (listen(server_sock, 1) < 0)
    {
        perror("Listen failed");
        close(server_sock);
        exit(EXIT_FAILURE);
    }

    printf("Waiting for TLS connection on port %d...\n", tls_server_port);

    struct sockaddr_in client_addr;
    socklen_t len = sizeof(client_addr);
    int client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &len);
    if (client_sock < 0)
    {
        perror("Accept failed");
        close(server_sock);
        exit(EXIT_FAILURE);
    }

    printf("Accepted client_socket=%d\n", client_sock);

    SSL *ssl = NULL;

    if (myAcceptSSL(ctx, client_sock, &ssl) <= 0)
    {
        fprintf(stderr, "SSL_accept failed\n");
        ERR_print_errors_fp(stderr);
    }
    else
    {
        printf("TLS connection established.\n");

        while (1)
        {
            char time_buf[128];
            time_t now = time(NULL);
            struct tm *tm_info = localtime(&now);
            strftime(time_buf, sizeof(time_buf), "time=%Y-%m-%d %H:%M:%S\n", tm_info);

            int sent = SSL_write(ssl, time_buf, strlen(time_buf));
            if (sent <= 0)
            {
                printf("Connection closed or write failed\n");
                ERR_print_errors_fp(stderr);
                break;
            }

            printf("Sent to client: %s", time_buf);
            fflush(stdout);
            sleep(1); // 1초 주기
        }
    }

    close(client_sock);
    close(server_sock);
    myFreeSSL(ctx, ssl);
    return 0;
}
#endif

int myFreeSSL(SSL_CTX *ctx, SSL *ssl)
{
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 0;
}
