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
    int fd;
    SSL *ssl;
    int port;
};

static struct tls_state *handshakes[65536] = {0};

// Set fd non-blocking
static void set_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void set_block(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
}

static void *tls_manager_loop(void *arg) {
    int epfd = epoll_create1(0);
    struct epoll_event ev, events[256];

    // Monitor the Request Pipe (EPOLLEXCLUSIVE properly balances threads!)
    ev.events = EPOLLIN | EPOLLEXCLUSIVE;
    ev.data.fd = tls_req_fd[0];
    epoll_ctl(epfd, EPOLL_CTL_ADD, tls_req_fd[0], &ev);

    while (1) {
        int n = epoll_wait(epfd, events, 256, -1);
        for (int i = 0; i < n; i++) {
            int active_fd = events[i].data.fd;

            // 1. New Request from Assembly loop
            if (active_fd == tls_req_fd[0]) {
                struct { int fd; int port; } req;
                // Reading 8 bytes per epoll_wait (FD + PORT)
                if (read(tls_req_fd[0], &req, 8) == 8) {
                    set_nonblock(req.fd);
                    SSL *ssl = SSL_new(g_ctx);
                    SSL_set_fd(ssl, req.fd);

                    struct tls_state *st = malloc(sizeof(struct tls_state));
                    st->fd = req.fd;
                    st->port = req.port;
                    st->ssl = ssl;
                    handshakes[req.fd] = st;

                    // Add client_fd to epoll to perform async SSL_accept
                    struct epoll_event cev;
                    cev.events = EPOLLIN | EPOLLOUT | EPOLLHUP | EPOLLERR | EPOLLET;
                    cev.data.fd = req.fd;
                    epoll_ctl(epfd, EPOLL_CTL_ADD, req.fd, &cev);
                    
                    // KICKSTART HANDSHAKE
                    active_fd = req.fd;
                    goto pump_handshake;
                }
                continue;
            }

pump_handshake:
            // 2. Client Handshake Progress
            struct tls_state *st = handshakes[active_fd];
            if (!st) continue; // Should not happen

            int ret = SSL_accept(st->ssl);
            if (ret == 1) {
                // SSL Handshake completed!
                epoll_ctl(epfd, EPOLL_CTL_DEL, active_fd, NULL);
                set_block(active_fd);
                
                // Verify if kTLS actually activated
                BIO *wbio = SSL_get_wbio(st->ssl);
                BIO *rbio = SSL_get_rbio(st->ssl);
                int ksend = wbio ? BIO_get_ktls_send(wbio) : 0;
                int krecv = rbio ? BIO_get_ktls_recv(rbio) : 0;
                
                FILE *f = fopen("/tmp/ktls_status.txt", "w");
                if (f) {
                    fprintf(f, "TX=%d RX=%d\n", ksend, krecv);
                    fclose(f);
                }

                if (ksend) {
                    // kTLS Successful Hardware Offload!
                    // Return raw fd AND preserved port to Assembly logic
                    SSL_set_fd(st->ssl, -1);
                    struct { int fd; int port; } res = { active_fd, st->port };
                    if (write(tls_res_fd[1], &res, 8) != 8) {
                        // Ignore write error silently to avoid blocking IO
                    }
                } else {
                    // Fallback userspace -> Reject connection!
                    close(active_fd);
                }
                SSL_free(st->ssl);
                free(st);
                handshakes[active_fd] = NULL;
                continue;
            } 
            
            // Still handshaking: evaluate errors
            int err = SSL_get_error(st->ssl, ret);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                // Must wait for more events, keep in epoll silently!
                continue;
            } else {
                // Hard Error (e.g. unknown protocol / client reset)
                epoll_ctl(epfd, EPOLL_CTL_DEL, active_fd, NULL);
                close(active_fd);
                SSL_free(st->ssl);
                free(st);
                handshakes[active_fd] = NULL;
            }
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

    // Force TLS 1.2 for flawless kTLS mapping
    SSL_CTX_set_min_proto_version(g_ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(g_ctx, TLS1_2_VERSION);

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
    
    // Set nonblock on pipes to prevent deadlocks
    set_nonblock(tls_req_fd[0]);
    set_nonblock(tls_res_fd[0]);

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
