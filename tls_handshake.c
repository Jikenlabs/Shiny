#include <openssl/ssl.h>
#include <openssl/err.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MAX_CONCURRENT_HANDSHAKES 8192

// Global context
static SSL_CTX *g_ctx = NULL;

// ASM interfaces
int tls_req_fd[2]; // ASM writes fd to req_fd[1], Manager reads req_fd[0]
int tls_res_fd[2]; // Manager writes fd to res_fd[1], ASM reads res_fd[0]

// Pending SSL states
struct tls_state {
    int fd;         // Real network socket
    int asm_fd;     // Internal side of socketpair (for proxying)
    SSL *ssl;
    int port;
    int is_proxy;   // 1 if we are acting as a decryption proxy for TLS 1.3
};

// Set fd non-blocking
static void set_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void set_block(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
}

static void cleanup_state(int epfd, struct tls_state *st) {
    if (!st) return;
    if (st->fd >= 0) {
        epoll_ctl(epfd, EPOLL_CTL_DEL, st->fd, NULL);
        close(st->fd);
    }
    if (st->asm_fd >= 0) {
        epoll_ctl(epfd, EPOLL_CTL_DEL, st->asm_fd, NULL);
        close(st->asm_fd);
    }
    if (st->ssl) SSL_free(st->ssl);
    free(st);
}

static void *tls_manager_loop(void *arg) {
    (void)arg;
    int epfd = epoll_create1(0);
    struct epoll_event ev, events[256];

    // Monitor the Request Pipe
    // Use (void*)1 to distinguish from tls_state pointers
    ev.events = EPOLLIN | EPOLLEXCLUSIVE;
    ev.data.ptr = (void*)1; 
    epoll_ctl(epfd, EPOLL_CTL_ADD, tls_req_fd[0], &ev);

    while (1) {
        int n = epoll_wait(epfd, events, 256, -1);
        for (int i = 0; i < n; i++) {
            struct tls_state *st = NULL;
            // 1. New Request from Assembly loop
            if (events[i].data.ptr == (void*)1) {
                struct { int fd; int port; } req;
                while (read(tls_req_fd[0], &req, 8) == 8) {
                    set_nonblock(req.fd);
                    SSL *ssl = SSL_new(g_ctx);
                    const char *tls_ver = getenv("SHINY_TLS_VERSION");
                    if (tls_ver && strcmp(tls_ver, "1.3") == 0) {
                        SSL_set_read_ahead(ssl, 0);
                        SSL_set_mode(ssl, SSL_MODE_RELEASE_BUFFERS);
                    }
                    SSL_set_fd(ssl, req.fd);

                    st = calloc(1, sizeof(struct tls_state));
                    st->fd = req.fd; st->asm_fd = -1; st->port = req.port; st->ssl = ssl;
                    struct epoll_event cev = { .events = EPOLLIN | EPOLLOUT | EPOLLET, .data.ptr = st };
                    epoll_ctl(epfd, EPOLL_CTL_ADD, st->fd, &cev);
                    int ret = SSL_accept(st->ssl);
                    if (ret == 1) goto handshake_done_final; 
                }
                continue;
            }

            // 2. Identification du contexte et du canal
            uintptr_t ptr_raw = (uintptr_t)events[i].data.ptr;
            st = (struct tls_state *)(ptr_raw & ~1UL);
            int is_asm_event = (ptr_raw & 1);
            if (!st) continue;

            // 3. Mode Proxy (Déchiffrement applicatif pour TLS 1.3 Keep-Alive)
            if (st->is_proxy) {
                char buf[16384];
                if (is_asm_event) {
                    // Données de l'Ouvrier ASM -> Chiffrement -> Réseau
                    int nread = read(st->asm_fd, buf, sizeof(buf));
                    if (nread > 0) SSL_write(st->ssl, buf, nread);
                    else if (nread == 0) cleanup_state(epfd, st);
                } else {
                    // Données du Réseau -> Déchiffrement -> Ouvrier ASM
                    int nread;
                    while ((nread = SSL_read(st->ssl, buf, sizeof(buf))) > 0) {
                        if (write(st->asm_fd, buf, nread) < 0) { /* Handle error if needed */ ; }
                    }
                    if (nread <= 0) {
                        int err = SSL_get_error(st->ssl, nread);
                        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) cleanup_state(epfd, st);
                    }
                }
                continue;
            }

            // 4. Suite du Handshake TLS
            int ret = SSL_accept(st->ssl);
            if (ret == 1) {
handshake_done_final: {
                BIO *wbio = SSL_get_wbio(st->ssl);
                BIO *rbio = SSL_get_rbio(st->ssl);
                int ksend = (wbio && BIO_get_ktls_send(wbio));
                int krecv = (rbio && BIO_get_ktls_recv(rbio));
                const char *tver = getenv("SHINY_TLS_VERSION");
                int is_13 = (tver && strcmp(tver, "1.3") == 0);

                if (ksend && (krecv || !is_13)) {
                    // Fast Path kTLS direct
                    epoll_ctl(epfd, EPOLL_CTL_DEL, st->fd, NULL);
                    set_block(st->fd);
                    char pre_buf[4096];
                    int pre_len = SSL_read(st->ssl, pre_buf, sizeof(pre_buf));
                    if (pre_len < 0) pre_len = 0;
                    SSL_set_fd(st->ssl, -1);
                    struct { int fd, port, data_len; char data[4096]; } msg = { st->fd, st->port, pre_len, {0} };
                    if (pre_len > 0) memcpy(msg.data, pre_buf, pre_len);
                    if (write(tls_res_fd[1], &msg, 12 + pre_len) < 0) { /* Silence warning */ ; }
                    st->fd = -1; cleanup_state(epfd, st);
                } else if (is_13) {
                    // Proxy Decrypt Path (Handover transparent via socketpair)
                    int p_fds[2];
                    if (socketpair(AF_UNIX, SOCK_STREAM, 0, p_fds) < 0) { cleanup_state(epfd, st); continue; }
                    set_nonblock(p_fds[0]);
                    st->asm_fd = p_fds[0];
                    st->is_proxy = 1;
                    struct epoll_event ev_net = { .events = EPOLLIN | EPOLLET, .data.ptr = st };
                    epoll_ctl(epfd, EPOLL_CTL_MOD, st->fd, &ev_net);
                    struct epoll_event ev_asm = { .events = EPOLLIN | EPOLLET, .data.ptr = (void*)((uintptr_t)st | 1) };
                    epoll_ctl(epfd, EPOLL_CTL_ADD, st->asm_fd, &ev_asm);
                    struct { int fd, port, data_len; } msg = { p_fds[1], st->port, 0 };
                    if (write(tls_res_fd[1], &msg, 12) < 0) { /* Silence warning */ ; }
                } else {
                    cleanup_state(epfd, st);
                }
              }
              continue;
            } 
            int err = SSL_get_error(st->ssl, ret);
            if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) cleanup_state(epfd, st);
        }
    }
    return NULL;
}

// Called once from Assembly master startup (BEFORE sys_fork)
void tls_ctx_init(void) {
    g_ctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX_set_options(g_ctx, SSL_OP_NO_TICKET); // Prevent TLS 1.3 Newsession Tickets crashing kTLS RX!
    SSL_CTX_set_num_tickets(g_ctx, 0);
    if (!g_ctx) return;

    // Select TLS version via environment variable (Default: TLS 1.2)
    const char *tls_ver = getenv("SHINY_TLS_VERSION");
    if (tls_ver && strcmp(tls_ver, "1.3") == 0) {
        SSL_CTX_set_min_proto_version(g_ctx, TLS1_3_VERSION);
        SSL_CTX_set_max_proto_version(g_ctx, TLS1_3_VERSION);
        
        // TLS 1.3 Default: AES-256-GCM (Overrideable via SHINY_TLS_CIPHER)
        const char *cipher = getenv("SHINY_TLS_CIPHER");
        if (!cipher) cipher = "TLS_AES_256_GCM_SHA384";
        SSL_CTX_set_ciphersuites(g_ctx, cipher);
    } else {
        // Force TLS 1.2 for flawless kTLS mapping
        SSL_CTX_set_min_proto_version(g_ctx, TLS1_2_VERSION);
        SSL_CTX_set_max_proto_version(g_ctx, TLS1_2_VERSION);
    }

    // EXTREMELY IMPORTANT: We force Native Kernel TLS (kTLS) injection!
    SSL_CTX_set_options(g_ctx, SSL_OP_ENABLE_KTLS);

    if (SSL_CTX_use_certificate_file(g_ctx, "server.crt", SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "[ERROR] TLS Cert file not found at server.crt\n");
        return;
    }
    
    if (SSL_CTX_use_PrivateKey_file(g_ctx, "server.key", SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "[ERROR] TLS Key file not found at server.key\n");
        return;
    }
}

// Called in the un-tracked Assembly worker process (AFTER sys_fork)
int tls_worker_init(void) {
    // Create Bidirectional Pipes exclusively for this worker instance
    if (pipe(tls_req_fd) < 0) return -1;
    if (pipe(tls_res_fd) < 0) return -1;
    
    // Set nonblock on ALL pipe ends to prevent deadlocks between ASM workers and TLS managers
    set_nonblock(tls_req_fd[0]);
    set_nonblock(tls_req_fd[1]);
    set_nonblock(tls_res_fd[0]);
    set_nonblock(tls_res_fd[1]);

    // Create a TLS thread pool (configurable via ENV, max 16 per worker)
    int num_threads = 4;
    char *env_threads = getenv("SHINY_TLS_THREADS");
    if (env_threads) {
        num_threads = atoi(env_threads);
        if (num_threads <= 0) num_threads = 1;
        if (num_threads > 16) num_threads = 16;
    }

    pthread_t tids[16];
    for (int i = 0; i < num_threads; i++) {
        pthread_create(&tids[i], NULL, tls_manager_loop, NULL);
    }

    return 0;
}
