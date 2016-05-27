#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/test.h>
#include <errno.h>

#include "common.h"

#define SERV_PORT 11111
#define MAX_LINE 4096
#define REQUEST "retrieve-secret"

int main(int argc, char **argv)
{
    if (argc != 4) {
        fail("Usage: client path/to/root/cert path/to/client/cert path/to/client/key");
    }

    const char *root_cert_path = argv[1];
    const char *client_cert_path = argv[2];
    const char *client_key_path = argv[3];

    int sockfd;
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    WOLFSSL_METHOD* method;
    struct  sockaddr_in servAddr;

    int n;
    char buf[MAX_LINE];

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_port = htons(SERV_PORT);

    connect(sockfd, (struct sockaddr *) &servAddr, sizeof(servAddr));

    wolfSSL_Init();

    method = wolfTLSv1_2_client_method();

    if ( (ctx = wolfSSL_CTX_new(method)) == NULL) {
        fail("wolfSSL_CTX_new error");
    }

    if (wolfSSL_CTX_load_verify_locations(ctx, root_cert_path, 0) != SSL_SUCCESS) {
        fail("Error loading root certificate");
    }

    if (wolfSSL_CTX_use_certificate_file(ctx, client_cert_path, SSL_FILETYPE_PEM) != SSL_SUCCESS) {
        fail("Error loading client certificate");
    }

    if (wolfSSL_CTX_use_PrivateKey_file(ctx, client_key_path, SSL_FILETYPE_PEM) != SSL_SUCCESS) {
        fail("Error loading client key");
    }

    if ( (ssl = wolfSSL_new(ctx)) == NULL) {
        fail("wolfSSL_new error");
    }


    wolfSSL_set_fd(ssl, sockfd);
    int res = wolfSSL_connect(ssl);

    if (res != SSL_SUCCESS) {
        fail("Failed to establish TLS connection");
    }

    if (wolfSSL_write(ssl, REQUEST, strlen(REQUEST)) != strlen(REQUEST)) {
        fail("Failed to send request");
    }

    if ((n = wolfSSL_read(ssl, buf, (sizeof(buf) - 1))) > 0) {
        printf("The secret is: %s\n", buf);
    }

    if (n < 0) {
        int error = wolfSSL_get_error(ssl, n);
        if (error == -330) {
            printf("Failed to verify the servers signature\n");
        } else {
            printf("wolfSSL_read_error = %d\n", error);
        }
    } else if (n == 0) {
        printf("Connection closed by peer\n");
    }

    printf("Shutting down...\n");

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();

    exit(EXIT_SUCCESS);
}

