#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 4443

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

SSL_CTX *create_context() {
    const SSL_METHOD *method = SSLv23_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

int main() {
    int sockfd, client_fd;
    struct sockaddr_in addr;
    char buffer[1024] = {0};

    init_openssl();
    SSL_CTX *ctx = create_context();
    configure_context(ctx);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    bind(sockfd, (struct sockaddr*)&addr, sizeof(addr));
    listen(sockfd, 5);

    printf("Waiting for a connection...\n");

    while (1) {
        client_fd = accept(sockfd, NULL, NULL);
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_fd);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        } else {
            printf("Client connected via TLS\n");
            SSL_read(ssl, buffer, sizeof(buffer));
            printf("Received: %s\n", buffer);
            SSL_write(ssl, "Hello, TLS Client!", 19);
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
    }

    close(sockfd);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    return 0;
}
