#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>


int main(int argc, char **argv) {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);

    if (!ctx) {
        return 1;
    }

    const char *server_addr = "0.0.0.0";
    int server_port = 443;

    // Create a TCP socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Cannot create socket");
        exit(EXIT_FAILURE);
    }

    // Convert server address
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(server_port);

    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, server_addr, &serv_addr.sin_addr) <= 0) {
        perror("Invalid address");
        exit(EXIT_FAILURE);
    }

    // Connect to the server
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection Failed");
        exit(EXIT_FAILURE);
    }

    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        return 1;
    }

    // Inform OpenSSL which socket to use
    if (!SSL_set_fd(ssl, sockfd)) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Attempt to connect
    int ret = SSL_connect(ssl);

    if (ret != 1) {
        ERR_print_errors_fp(stderr);
        return 1;
    }
    printf("SSL/TLS handshake completed.\n");

    // send http request
    const char *msg = "GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n";
    SSL_write(ssl, msg, strlen(msg));


    // Clean up
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(sockfd);

    return 0;
}
