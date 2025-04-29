/**
 * @author Keaton Szantho
 * @brief This program carries out the server side of the file transfer to the client.
 * It uses HMAC and SHA-256 to authenticate the client before the files are sent to them. RSA will be
 * used to generate the private and public key.
 *
 */

 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <unistd.h>
 #include <pthread.h>
 #include <netinet/in.h>
 #include <arpa/inet.h>
 #include <openssl/rsa.h>
 #include <openssl/pem.h>
 #include <openssl/err.h>
 #include <openssl/rand.h>
 #include <openssl/hmac.h>
 #include <limits.h>
 #include <linux/limits.h>
 
 #define BACKLOG 10
 #define BUFFER_SIZE 4096
 #define DOWNLOAD_DIR "downloads"
 #define HMAC_KEY_FILE "hmac_key.bin"
 
 typedef struct {
     int client_fd;
     RSA *client_pub;
     unsigned char *hmac_key;
     int hmac_key_len;
 } client_args_t;
 
 // Load an RSA private key from file
 static RSA *load_private_key(const char *keyfile) {
     FILE *fp = fopen(keyfile, "r");
     if (!fp) { perror("fopen private"); return NULL; }
     RSA *rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
     fclose(fp);
     return rsa;
 }
  static RSA *load_public_key(const char *keyfile) {
     FILE *fp = fopen(keyfile, "r");
     if (!fp) { perror("fopen public"); return NULL; }
     RSA *rsa = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL);
     fclose(fp);
     return rsa;
 }
 
 // Load raw HMAC key from file
 static unsigned char *load_hmac_key(const char *keyfile, int *out_len) {
     FILE *fp = fopen(keyfile, "rb");
     if (!fp) { perror("fopen hmac"); return NULL; }
     fseek(fp, 0, SEEK_END);
     long len = ftell(fp);
     fseek(fp, 0, SEEK_SET);
     if (len <= 0) { fclose(fp); return NULL; }
     unsigned char *key = malloc(len);
     if (!key) { fclose(fp); return NULL; }
     if (fread(key, 1, len, fp) != (size_t)len) {
         free(key);
         fclose(fp);
         return NULL;
     }
     fclose(fp);
     *out_len = (int)len;
     return key;
 }
 
 // Authenticate using nonce
 static int authenticate_client(int client_fd, RSA *client_pub) {
     unsigned char nonce[32];
     unsigned char signature[BUFFER_SIZE];
     uint32_t net_sig_len;
     unsigned int sig_len;
 
     // Generate nonce and error checking
     if (!RAND_bytes(nonce, sizeof(nonce))) {
         fprintf(stderr, "Failed to generate nonce\n");
         return 0;
     }
     // Send nonce to client
     if (write(client_fd, nonce, sizeof(nonce)) != sizeof(nonce)) return 0;
 
     if (read(client_fd, &net_sig_len, sizeof(net_sig_len)) != sizeof(net_sig_len)) return 0;
     sig_len = ntohl(net_sig_len);
     if (sig_len > sizeof(signature)) return 0;
 
     // Read signature
     if (read(client_fd, signature, sig_len) != (ssize_t)sig_len) return 0;
 
     if (RSA_verify(NID_sha256, nonce, sizeof(nonce), signature, sig_len, client_pub) != 1) {
         fprintf(stderr, "Client authentication failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
         return 0;
     }
     return 1;
 }
 
 // Compute HMAC-SHA256
 static unsigned char *compute_hmac(const unsigned char *data, size_t data_len,
                                    const unsigned char *key, int key_len,
                                    unsigned int *out_len) {
     return HMAC(EVP_sha256(), key, key_len, data, data_len, NULL, out_len);
 }
 
 static void *handle_client(void *arg) {
     client_args_t *c = arg;
     int fd = c->client_fd;
     char filepath[PATH_MAX];
     char fullpath[PATH_MAX + 20];
     ssize_t n;
 
     // Authenticate
     if (!authenticate_client(fd, c->client_pub)) {
         close(fd);
         free(c);
         return NULL;
     }
 
     if ((n = read(fd, filepath, sizeof(filepath)-1)) <= 0) {
         close(fd);
         free(c);
         return NULL;
     }
     filepath[n] = '\0';
     snprintf(fullpath, sizeof(fullpath), "%s/%s", DOWNLOAD_DIR, filepath);
 
     // Open the file
     FILE *f = fopen(fullpath, "rb");
     int32_t status = (f ? 0 : -1);
     int32_t net_status = htonl(status);
     write(fd, &net_status, sizeof(net_status));
     if (!f) {
         close(fd);
         free(c);
         return NULL;
     }
 
     // Stream file in chunks with HMAC
     unsigned char buf[BUFFER_SIZE];
     while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
         unsigned int hlen;
         unsigned char *hmac = compute_hmac(buf, n, c->hmac_key, c->hmac_key_len, &hlen);
         uint32_t net_n = htonl((uint32_t)n);
         uint32_t net_hlen = htonl(hlen);
         write(fd, &net_n, sizeof(net_n));
         write(fd, &net_hlen, sizeof(net_hlen));
         write(fd, hmac, hlen);
         write(fd, buf, n);
     }
     // end-of-file
     uint32_t zero = 0;
     write(fd, &zero, sizeof(zero));
 
     fclose(f);
     close(fd);
     free(c);
     return NULL;
 }
 
 // Start server on a single port
 static int start_server(int port, RSA *server_priv, RSA *client_pub,
                         unsigned char *hmac_key, int hmac_key_len) {
     int sockfd = socket(AF_INET, SOCK_STREAM, 0);
     if (sockfd < 0) { perror("socket"); return -1; }
 
     struct sockaddr_in addr = {0};
     addr.sin_family = AF_INET;
     addr.sin_addr.s_addr = INADDR_ANY;
     addr.sin_port = htons(port);
 
     if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
         perror("bind"); close(sockfd); return -1;
     }
     if (listen(sockfd, BACKLOG) < 0) {
         perror("listen"); close(sockfd); return -1;
     }
     printf("Server listening on port %d\n", port);
 
     while (1) {
         int client_fd = accept(sockfd, NULL, NULL);
         if (client_fd < 0) { perror("accept"); continue; }
         client_args_t *c = calloc(1, sizeof(*c));
         c->client_fd = client_fd;
         c->client_pub = client_pub;
         c->hmac_key = hmac_key;
         c->hmac_key_len = hmac_key_len;
         pthread_t tid;
         pthread_create(&tid, NULL, handle_client, c);
         pthread_detach(tid);
     }
     close(sockfd);
     return 0;
 }
 
 int main(int argc, char **argv) {
     if (argc < 2) {
         fprintf(stderr, "Usage: %s <port1> [<port2>] ...\n", argv[0]);
         return EXIT_FAILURE;
     }
 
     OpenSSL_add_all_algorithms();
     ERR_load_crypto_strings();
     
     //create RSA keys
     RSA *server_priv = load_private_key("server_priv.pem");
     RSA *client_pub = load_public_key("client_pub.pem");
     if (!server_priv || !client_pub) {
         fprintf(stderr, "Key load error\n");
         return EXIT_FAILURE;
     }

     int hmac_key_len;
     unsigned char *hmac_key = load_hmac_key(HMAC_KEY_FILE, &hmac_key_len);
     if (!hmac_key) {
         fprintf(stderr, "HMAC key load error\n");
         return EXIT_FAILURE;
     }
 
     // Launch a server thread for each port
     for (int i = 1; i < argc; i++) {
         int port = atoi(argv[i]);
         pthread_t tid;
         int *pport = malloc(sizeof(int)); *pport = port;
         pthread_create(&tid, NULL, (void*(*)(void*))start_server,
                        (void*)(intptr_t)port);
         // shared rsa and hmac_key are global
         pthread_detach(tid);
     }
     // Main thread sleeps to keep open
     pause();
 
     RSA_free(server_priv);
     RSA_free(client_pub);
     free(hmac_key);
     return EXIT_SUCCESS;
 } 