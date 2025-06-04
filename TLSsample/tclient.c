#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "tls.h"

int main(int argc, char *argv[])
{
    const char *tls_server_ip = TLS_SERVER_IP;
    int tls_server_port = TLS_SERVER_PORT;

    if (argc >= 2)
        tls_server_ip = argv[1];
    if (argc >= 3)
        tls_server_port = atoi(argv[2]);
    printf("tls client connects to %s:%d\n", tls_server_ip, tls_server_port);

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx)
    {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // 서버 인증서 검증을 위한 신뢰할 CA 인증서 설정 (시험용: 서버 인증서 직접 사용)
    if (!SSL_CTX_load_verify_locations(ctx, SERVER_CERT_FILE, NULL))
    {
        fprintf(stderr, "Failed to load server CA certificate\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // 클라이언트 인증서와 개인키 설정
    if (SSL_CTX_use_certificate_file(ctx, CLIENT_CERT_FILE, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, CLIENT_KEY_FILE, SSL_FILETYPE_PEM) <= 0)
    {
        fprintf(stderr, "Failed to load client certificate/key\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    // TCP 소켓 연결
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(tls_server_port);
    inet_pton(AF_INET, tls_server_ip, &server_addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) != 0)
    {
        perror("Connection to server failed");
        close(sock);
        exit(EXIT_FAILURE);
    }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) <= 0)
    {
        fprintf(stderr, "SSL_connect failed\n");
        ERR_print_errors_fp(stderr);
    }
    else
    {
        printf("TLS connection established with %s encryption\n", SSL_get_cipher(ssl));

        // 서버로부터 지속적으로 시간 수신
        char buf[1024];
        while (1)
        {
            memset(buf, 0, sizeof(buf));
            int bytes = SSL_read(ssl, buf, sizeof(buf) - 1);
            if (bytes <= 0)
            {
                printf("Connection closed or read failed\n");
                ERR_print_errors_fp(stderr);
                break;
            }
            printf("Received: %s", buf);
            fflush(stdout);
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    return 0;
}
