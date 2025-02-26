#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#define SERVER_IP "127.0.0.1"
#define PORT 4443

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

SSL_CTX *create_context() {
    const SSL_METHOD *method = SSLv23_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    ENGINE *engine;
    const char *engine_id = "pkcs11";
    const char *pkcs11_key_id = "pkcs11:id=01;type=private";
    const char *pkcs11_cert_id = "pkcs11:id=01;type=cert";
    const char *pin = "0000";

    // Load the PKCS#11 engine
    ENGINE_load_dynamic();
    engine = ENGINE_by_id(engine_id);
    if (!engine) {
        fprintf(stderr, "Failed to load PKCS#11 engine\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Initialize the engine
    if (!ENGINE_init(engine)) {
        fprintf(stderr, "Failed to initialize PKCS#11 engine\n");
        ERR_print_errors_fp(stderr);
        ENGINE_free(engine);
        exit(EXIT_FAILURE);
    }

    // Set the engine as the default for all cryptographic operations
    if (!ENGINE_set_default(engine, ENGINE_METHOD_ALL)) {
        fprintf(stderr, "Failed to set PKCS#11 engine as default\n");
        ERR_print_errors_fp(stderr);
        ENGINE_free(engine);
        exit(EXIT_FAILURE);
    }

    ENGINE_ctrl_cmd(engine,"PIN",0,pin,NULL,0);

    // Load and trust the CA certificate for server verification
    if (SSL_CTX_load_verify_locations(ctx, "ca-cert.pem", NULL) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_certificate_file(ctx, "client-cert.pem", SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    // Load private key from PKCS#11
    EVP_PKEY *pkey = ENGINE_load_private_key(engine, pkcs11_key_id, NULL, NULL);
    if (!pkey) {
        fprintf(stderr, "Failed to load private key from PKCS#11\n");
        ERR_print_errors_fp(stderr);
        ENGINE_free(engine);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey(ctx, pkey) <= 0) {
        fprintf(stderr, "Failed to use the private key\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(pkey);
        ENGINE_free(engine);
        exit(EXIT_FAILURE);
    }

   
    



    // Verify that the private key matches the certificate
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the certificate public key\n");
        exit(EXIT_FAILURE);
    }

    // Enforce server certificate verification
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    // Free the engine
    ENGINE_free(engine);
}

int main() {
    int sockfd;
    struct sockaddr_in addr;
    char buffer[1024] = "Hello, TLS Server!";
    
    init_openssl();
    SSL_CTX *ctx = create_context();
    configure_context(ctx);
    SSL *ssl = SSL_new(ctx);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    inet_pton(AF_INET, SERVER_IP, &addr.sin_addr);

    if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    SSL_set_fd(ssl, sockfd);
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        printf("Connected and verified the server\n");
        SSL_write(ssl, buffer, strlen(buffer));
        SSL_read(ssl, buffer, sizeof(buffer));
        printf("Received: %s\n", buffer);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    return 0;
}
