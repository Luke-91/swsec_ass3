#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/test.h>
#include <errno.h>

#include "common.h"

#define SERV_PORT 11111
#define MAX_LINE 4096
#define SECRET "the wolf dead"
#define VALID_REQUEST "retrieve-secret"

WOLFSSL_EVP_PKEY *client_key = NULL;

int verify_client_cert(int preverify, WOLFSSL_X509_STORE_CTX* store)
{
    if (store->error != 0 && store->error != ASN_NO_SIGNER_E) {
        printf("Error validating certificate.\n");
        return 0;
    }

    // verify that the client is authorized
    WOLFSSL_X509 *peer = store->current_cert;
    if (peer) {
        char* subject = wolfSSL_X509_get_subjectCN(peer);
        printf("'%s' is requesting access\n", subject);

        WOLFSSL_EVP_PKEY *pkey = wolfSSL_X509_get_pubkey(peer);

        int s1 = client_key->pkey_sz;
        int s2 = pkey->pkey_sz;

        if (s1 != s2) {
            printf("The length of the public keys do not match");
            return 0; // reject
        }

        if (memcmp(client_key->pkey.ptr, pkey->pkey.ptr, s1) == 0) {
            return 1; // accept
        } else {
            printf("Public key does not match. Reject.\n");
        }
    }

    return 0; // reject by default
}

void pin_client_key(const char *file) {
    WOLFSSL_X509 *client_cert = wolfSSL_X509_load_certificate_file(file, SSL_FILETYPE_PEM);
    client_key = wolfSSL_X509_get_pubkey(client_cert);
}

void handle_request(WOLFSSL_CTX *ctx, int connfd)
{
    int n;
    char buf[MAX_LINE];

    WOLFSSL *ssl;

    if ( (ssl = wolfSSL_new(ctx)) == NULL) {
        fail("wolfSSL_new error");
    }

    wolfSSL_set_fd(ssl, connfd);

    if ( (n = wolfSSL_read(ssl, buf, (sizeof(buf) -1))) > 0) {
        printf("Successfully authenticated client\n");
        printf("Got request: %s\n", buf);

        if (strcmp(VALID_REQUEST, buf) == 0) {
            if (wolfSSL_write(ssl, SECRET, strlen(SECRET)) != strlen(SECRET)) {
                fail("wolfSSL_write error");
            }
        } else {
            const char *err = "Invalid request.";
             if (wolfSSL_write(ssl, err, strlen(err)) != strlen(err)) {
                fail("wolfSSL_write error");
            }
        }
    }

    if (n < 0) {
        int error = wolfSSL_get_error(ssl, n);
        char buffer[WOLFSSL_MAX_ERROR_SZ];
        wolfSSL_ERR_error_string(error, buffer);
        printf("wolfSSL_read error = %d, %s\n", error, buffer);
    } else if (n == 0) {
        printf("Connection closed by peer\n");
    }

    wolfSSL_free(ssl);
}

int main(int argc, char** argv)
{
    if (argc != 4) {
        fail("Usage: ./server path/to/server/cert path/to/server/key path/to/client/cert");
    }

    const char *server_cert_path = argv[1];
    const char *server_key_path = argv[2];
    const char *client_cert_path = argv[3];

    pin_client_key(client_cert_path);

    int listenfd, connfd;
    WOLFSSL_CTX* ctx;
    WOLFSSL_METHOD* method;

    wolfSSL_Init();
    method = wolfTLSv1_2_server_method();

    if ( (ctx = wolfSSL_CTX_new(method)) == NULL) {
        fail("wolfSSL_CTX_new error");
    }

    if (wolfSSL_CTX_use_certificate_file(ctx, server_cert_path, SSL_FILETYPE_PEM) != SSL_SUCCESS) {
        fail("Error loading server certificate");
    }

    if (wolfSSL_CTX_use_PrivateKey_file(ctx, server_key_path, SSL_FILETYPE_PEM) != SSL_SUCCESS) {
        fail("Error loading server key");
    }

    wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_client_cert);

    word16 port = SERV_PORT;
    tcp_listen(&listenfd, &port, 0, 0);

    /* answer incoming requests */
    while (1) {
        tcp_accept(&listenfd, &connfd, NULL, SERV_PORT, 0, 0, 0, 0);
        handle_request(ctx, connfd);
        close(connfd);
    }

    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();

    exit(EXIT_SUCCESS);
}

