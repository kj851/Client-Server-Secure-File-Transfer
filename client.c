/**
 * @author Keaton Szantho
 * @brief This program handles the client side 
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define BUFFER_SIZE 4096

// Load the client's private key
RSA *load_private_key(const char *keyfile) {
    FILE *fp = fopen(keyfile, "r");
    if (!fp) { perror("fopen"); return NULL; }
    RSA *rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    return rsa;
}

// Load the server's public key (for verifying HMAC if needed)
RSA *load_public_key(const char *keyfile) {
    FILE *fp = fopen(keyfile, "r");
    if (!fp) { perror("fopen"); return NULL; }
    RSA *rsa = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    return rsa;
}

int authenticate_server(int sockfd, RSA *client_priv) {
    unsigned char nonce[32];
    unsigned char signature[BUFFER_SIZE];
    unsigned char *sig = NULL;
    unsigned int sig_len;
    uint32_t net_sig_len;

    // Read server nonce
    if (read(sockfd, nonce, sizeof(nonce)) != sizeof(nonce)) return 0;

    // Sign nonce
    sig_len = RSA_size(client_priv);
    if ((sig = malloc(sig_len)) == NULL) return 0;
    if (RSA_sign(NID_sha256, nonce, sizeof(nonce), sig, &sig_len, client_priv) != 1) {
        free(sig);
        return 0;
    }

    // Send signature length and signature
    net_sig_len = htonl(sig_len);
    write(sockfd, &net_sig_len, sizeof(net_sig_len));
    write(sockfd, sig, sig_len);
    free(sig);

    // TODO: Optionally verify server response
    return 1;
}

int connect_with_failover(const char *primary_ip, int primary_port,
                          const char *secondary_ip, int secondary_port) {
    int sockfd;
    struct sockaddr_in addr;

    // Try primary
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return -1;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(primary_port);
    inet_pton(AF_INET, primary_ip, &addr.sin_addr);
    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
        return sockfd;
    }
    close(sockfd);

    // Try secondary
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(secondary_port);
    inet_pton(AF_INET, secondary_ip, &addr.sin_addr);
    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
        return sockfd;
    }
    close(sockfd);
    return -1;
}

int main(int argc, char **argv) {
    if (argc != 6) {
        fprintf(stderr, "Usage: %s <primary_ip> <primary_port> <secondary_ip> <secondary_port> <file_path>\n", argv[0]);
        return EXIT_FAILURE;
    }
    const char *pri_ip = argv[1];
    int pri_port = atoi(argv[2]);
    const char *sec_ip = argv[3];
    int sec_port = atoi(argv[4]);
    const char *file_path = argv[5];

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    RSA *client_priv = load_private_key("client_priv.pem");
    if (!client_priv) { fprintf(stderr, "Failed to load client key\n"); return EXIT_FAILURE; }

    int sockfd = connect_with_failover(pri_ip, pri_port, sec_ip, sec_port);
    if (sockfd < 0) {
        fprintf(stderr, "Unable to connect to both primary and secondary servers\n");
        return EXIT_FAILURE;
    }

    // Authenticate to server
    if (!authenticate_server(sockfd, client_priv)) {
        fprintf(stderr, "Authentication failed\n");
        close(sockfd);
        return EXIT_FAILURE;
    }

    // Request file
    write(sockfd, file_path, strlen(file_path) + 1);
    
    char buffer[BUFFER_SIZE];
    ssize_t n;
    while ((n = read(sockfd, buffer, sizeof(buffer))) > 0) {
        write(STDOUT_FILENO, buffer, n);
    }

    close(sockfd);
    RSA_free(client_priv);
    return EXIT_SUCCESS;
}
