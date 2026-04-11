#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>

extern unsigned short sockaddr_port;
extern char doc_root[256];
extern unsigned char xdp_enabled;
extern unsigned char tls_enabled;
extern unsigned char zc_enabled;
extern unsigned char uring_enabled;
extern unsigned int worker_count_global;
extern unsigned int proxy_pool_size_global;

extern unsigned char access_log_enabled;
extern unsigned char tcp_nopush_enabled;
extern unsigned char tcp_nodelay_enabled;
extern unsigned char reuseport_enabled;
extern unsigned int worker_connections_global;

// Native port SSL map exported mapping
uint8_t port_is_ssl[65536] = {0};
extern unsigned char proxy_http_version_1_1;
extern unsigned char proxy_set_keepalive;

#define MULTIPLIER 1
struct upstream_group {
    char name[32];
    int server_count;
    int algorithm; // 0=RR, 1=IP_HASH, 2=LEAST_CONN
    short families[16];
    char addrs[16][106];
    long current_rr;
    long active_connections[16];
};
struct upstream_group upstreams_list[16];
int upstreams_count = 0;
int current_upstream = -1;

#pragma pack(push, 1)
struct location {
    char path[32];
    short proxy_family;
    char proxy_addr[106]; // Exact fit for AF_UNIX path or AF_INET struct
    unsigned short is_proxy;
    unsigned short splice_mode;
};

struct vhost {
    char domain[64];
    char doc_root[252];
    unsigned short port;
    unsigned short loc_count;
    struct location locs[4];
    unsigned short index_count;
    char padding_align[6];
    char index_files[4][24];
    
    unsigned short is_ssl;
    char ssl_cert[256];
    char ssl_key[256];
    
    char padding[534]; // Exactly 2048 bytes total
};
#pragma pack(pop)
extern struct vhost vhosts[16];
extern unsigned int vhost_count_global;

struct mime_mapping {
    char ext[8];          // null-terminated extension, e.g. ".html"
    char mime[64];        // null-terminated MIME type, e.g. "text/html"
};
// Export matching ASM requirement
struct mime_mapping mime_dict[64];
unsigned int mime_count_global = 9;

// Default basic mapping
static void init_mime_dict() {
    strcpy(mime_dict[0].ext, ".html"); strcpy(mime_dict[0].mime, "text/html; charset=UTF-8");
    strcpy(mime_dict[1].ext, ".js");   strcpy(mime_dict[1].mime, "application/javascript");
    strcpy(mime_dict[2].ext, ".css");  strcpy(mime_dict[2].mime, "text/css");
    strcpy(mime_dict[3].ext, ".json"); strcpy(mime_dict[3].mime, "application/json");
    strcpy(mime_dict[4].ext, ".png");  strcpy(mime_dict[4].mime, "image/png");
    strcpy(mime_dict[5].ext, ".jpg");  strcpy(mime_dict[5].mime, "image/jpeg");
    strcpy(mime_dict[6].ext, ".svg");  strcpy(mime_dict[6].mime, "image/svg+xml");
    strcpy(mime_dict[7].ext, ".mp4");  strcpy(mime_dict[7].mime, "video/mp4");
    strcpy(mime_dict[8].ext, ".txt");  strcpy(mime_dict[8].mime, "text/plain");
}

// Simple custom atoi
static int my_atoi(const char *s) {
    int n = 0;
    while (*s >= '0' && *s <= '9') {
        n = n * 10 + (*s - '0');
        s++;
    }
    return n;
}

// Convert little-endian port to Network Byte Order (htons)
static unsigned short my_htons(unsigned short port) {
    return (port >> 8) | (port << 8);
}

// Very basic C tokenizer for Nginx-like config
void parse_nginx_config(const char *filepath) {
    // Defaults matching ASM
    sockaddr_port = my_htons(8080);
    worker_count_global = 0; // 0 means auto
    proxy_pool_size_global = 32; // default pool size
    vhost_count_global = 0;
    
    access_log_enabled = 1;
    tcp_nopush_enabled = 1;
    tcp_nodelay_enabled = 1;
    reuseport_enabled = 0;
    worker_connections_global = 65535;

    init_mime_dict();
    
    if (!filepath) filepath = "shiny.conf";
    int fd = open(filepath, O_RDONLY);
    if (fd < 0) return;
    
    char buf[4096];
    int len = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (len <= 0) return;
    buf[len] = '\0';
    
    char *p = buf;
    int current_vhost = -1;
    
    while (*p) {
        // Skip whitespace
        if (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == '{' || *p == '}') {
            p++;
            continue;
        }
        
        // Skip comments
        if (*p == '#') {
            while (*p && *p != '\n') p++;
            continue;
        }

        // Match server block loosely
        if (strncmp(p, "server", 6) == 0 && (p[6] == ' ' || p[6] == '\t' || p[6] == '\n' || p[6] == '\r' || p[6] == '{')) {
            char *tmpp = p + 6;
            while (*tmpp == ' ' || *tmpp == '\t' || *tmpp == '\n' || *tmpp == '\r') tmpp++;
            if (*tmpp == '{') {
                current_upstream = -1; // End upstream parsing
                current_vhost++;
                if (current_vhost >= 16) current_vhost = 15;
                vhost_count_global = current_vhost + 1;
                for(int i=0; i<64; i++) vhosts[current_vhost].domain[i] = '\0';
                for(int i=0; i<252; i++) vhosts[current_vhost].doc_root[i] = '\0';
                vhosts[current_vhost].loc_count = 0;
                for(int j=0; j<4; j++) vhosts[current_vhost].locs[j].is_proxy = 0;
                vhosts[current_vhost].index_count = 1;
                for(int j=0; j<4; j++) for(int k=0; k<24; k++) vhosts[current_vhost].index_files[j][k] = '\0';
                strcpy(vhosts[current_vhost].index_files[0], "index.html");
                p = tmpp + 1;
                continue;
            }
        }
        
        // Match server_name
        if (strncmp(p, "server_name", 11) == 0) {
            p += 11;
            while (*p == ' ' || *p == '\t') p++;
            char *start = p;
            while (*p && *p != ';' && *p != ' ' && *p != '\n' && *p != '\r') p++;
            int len = p - start;
            if (current_vhost >= 0 && len > 0 && len < 63) {
                memcpy(vhosts[current_vhost].domain, start, len);
            }
            while (*p && *p != ';') p++;
            if (*p == ';') p++;
            continue;
        }
        
        // Match worker_processes
        if (strncmp(p, "worker_processes", 16) == 0) {
            p += 16;
            while (*p == ' ' || *p == '\t') p++;
            if (strncmp(p, "auto", 4) == 0) {
                worker_count_global = 0; // Auto
            } else {
                worker_count_global = my_atoi(p);
            }
            while (*p && *p != ';') p++;
            if (*p == ';') p++;
            continue;
        }

        // Match worker_rlimit_nofile
        if (strncmp(p, "worker_rlimit_nofile", 20) == 0) {
            p += 20;
            while (*p == ' ' || *p == '\t') p++;
            int limit = my_atoi(p);
            if (limit > 0) {
                struct rlimit rl;
                rl.rlim_cur = limit;
                rl.rlim_max = limit;
                setrlimit(RLIMIT_NOFILE, &rl);
            }
            while (*p && *p != ';') p++;
            if (*p == ';') p++;
            continue;
        }

        // Match use io_uring
        if (strncmp(p, "use io_uring", 12) == 0) {
            p += 12;
            uring_enabled = 1;
            while (*p && *p != ';') p++;
            if (*p == ';') p++;
            continue;
        }

        // Match access_log
        if (strncmp(p, "access_log", 10) == 0) {
            p += 10;
            while (*p == ' ' || *p == '\t') p++;
            if (strncmp(p, "off", 3) == 0) access_log_enabled = 0;
            else if (strncmp(p, "on", 2) == 0) access_log_enabled = 1;
            while (*p && *p != ';') p++;
            if (*p == ';') p++;
            continue;
        }

        // Match tcp_nopush
        if (strncmp(p, "tcp_nopush", 10) == 0) {
            p += 10;
            while (*p == ' ' || *p == '\t') p++;
            if (strncmp(p, "off", 3) == 0) tcp_nopush_enabled = 0;
            else if (strncmp(p, "on", 2) == 0) tcp_nopush_enabled = 1;
            while (*p && *p != ';') p++;
            if (*p == ';') p++;
            continue;
        }

        // Match tcp_nodelay
        if (strncmp(p, "tcp_nodelay", 11) == 0) {
            p += 11;
            while (*p == ' ' || *p == '\t') p++;
            if (strncmp(p, "off", 3) == 0) tcp_nodelay_enabled = 0;
            else if (strncmp(p, "on", 2) == 0) tcp_nodelay_enabled = 1;
            while (*p && *p != ';') p++;
            if (*p == ';') p++;
            continue;
        }

        // Match upstream block
        if (strncmp(p, "upstream", 8) == 0 && (p[8] == ' ' || p[8] == '\t')) {
            char *tmpp = p + 8;
            while (*tmpp == ' ' || *tmpp == '\t') tmpp++;
            char *name_start = tmpp;
            while (*tmpp && *tmpp != ' ' && *tmpp != '{' && *tmpp != '\n' && *tmpp != '\r') tmpp++;
            int name_len = tmpp - name_start;
            if (upstreams_count < 16 && name_len > 0 && name_len < 31) {
                current_upstream = upstreams_count++;
                memset(&upstreams_list[current_upstream], 0, sizeof(struct upstream_group));
                memcpy(upstreams_list[current_upstream].name, name_start, name_len);
                upstreams_list[current_upstream].name[name_len] = '\0';
                upstreams_list[current_upstream].server_count = 0;
                upstreams_list[current_upstream].algorithm = 0; // RR by default
            }
            while (*tmpp && *tmpp != '{') tmpp++;
            if (*tmpp == '{') p = tmpp + 1;
            else p = tmpp;
            continue;
        }

        // Match parsing inside upstream algorithms
        if (strncmp(p, "ip_hash", 7) == 0) {
            if (current_upstream >= 0) upstreams_list[current_upstream].algorithm = 1;
            p += 7;
            while (*p && *p != ';') p++;
            if (*p == ';') p++;
            continue;
        }

        if (strncmp(p, "least_conn", 10) == 0) {
            if (current_upstream >= 0) upstreams_list[current_upstream].algorithm = 2;
            p += 10;
            while (*p && *p != ';') p++;
            if (*p == ';') p++;
            continue;
        }

        // Match worker_connections
        if (strncmp(p, "worker_connections", 18) == 0) {
            p += 18;
            while (*p == ' ' || *p == '\t') p++;
            worker_connections_global = my_atoi(p);
            while (*p && *p != ';') p++;
            if (*p == ';') p++;
            continue;
        }

        // Match proxy_http_version
        if (strncmp(p, "proxy_http_version", 18) == 0) {
            p += 18;
            while (*p == ' ' || *p == '\t') p++;
            if (strncmp(p, "1.1", 3) == 0) proxy_http_version_1_1 = 1;
            while (*p && *p != ';') p++;
            if (*p == ';') p++;
            continue;
        }

        // Match proxy_set_header
        if (strncmp(p, "proxy_set_header", 16) == 0) {
            p += 16;
            while (*p == ' ' || *p == '\t') p++;
            if (strncmp(p, "Connection", 10) == 0) {
                p += 10;
                while (*p == ' ' || *p == '\t') p++;
                if (strncmp(p, "\"keep-alive\"", 12) == 0 || strncmp(p, "keep-alive", 10) == 0) {
                    proxy_set_keepalive = 1;
                }
            }
            while (*p && *p != ';') p++;
            if (*p == ';') p++;
            continue;
        }

        // Match keepalive (inside upstream or http)
        if (strncmp(p, "keepalive", 9) == 0 && (p[9] == ' ' || p[9] == '\t')) {
            p += 9;
            while (*p == ' ' || *p == '\t') p++;
            int val = my_atoi(p);
            if (val > 0 && val <= 256) proxy_pool_size_global = val;
            while (*p && *p != ';') p++;
            if (*p == ';') p++;
            continue;
        }
        
        // Match listen
        if (strncmp(p, "listen", 6) == 0) {
            p += 6;
            while (*p == ' ' || *p == '\t') p++;
            int port = my_atoi(p);
            if (port > 0 && port < 65536) {
                if (current_vhost >= 0) {
                    vhosts[current_vhost].port = my_htons((unsigned short)port);
                } else {
                    sockaddr_port = my_htons((unsigned short)port);
                }
            }
            while (*p && *p != ';' && *p != ' ' && *p != '\n' && *p != '\r') p++;
            while (*p == ' ' || *p == '\t') p++;
            if (strncmp(p, "ssl", 3) == 0) {
                if (current_vhost >= 0) vhosts[current_vhost].is_ssl = 1;
                // port MUST be in network byte order to match Assembly ACCEPT payload!
                unsigned short host_port = my_htons((unsigned short)port);
                port_is_ssl[host_port] = 1;

                tls_enabled = 1; // Any SSL vhost instantly activates the global manager hook
                p += 3;
            }
            while (*p == ' ' || *p == '\t') p++;
            if (strncmp(p, "reuseport", 9) == 0) {
                reuseport_enabled = 1;
                p += 9;
            }
            while (*p && *p != ';') p++;
            if (*p == ';') p++;
            continue;
        }
        
        // Match ssl_certificate_key
        if (strncmp(p, "ssl_certificate_key", 19) == 0) {
            p += 19;
            while (*p == ' ' || *p == '\t') p++;
            char *start = p;
            while (*p && *p != ';' && *p != ' ' && *p != '\n' && *p != '\r') p++;
            int len = p - start;
            if (current_vhost >= 0 && len > 0 && len < 255) {
                memcpy(vhosts[current_vhost].ssl_key, start, len);
                vhosts[current_vhost].ssl_key[len] = '\0';
            }
            while (*p && *p != ';') p++;
            if (*p == ';') p++;
            continue;
        }

        // Match ssl_certificate (Must be AFTER ssl_certificate_key check)
        if (strncmp(p, "ssl_certificate", 15) == 0) {
            p += 15;
            while (*p == ' ' || *p == '\t') p++;
            char *start = p;
            while (*p && *p != ';' && *p != ' ' && *p != '\n' && *p != '\r') p++;
            int len = p - start;
            if (current_vhost >= 0 && len > 0 && len < 255) {
                memcpy(vhosts[current_vhost].ssl_cert, start, len);
                vhosts[current_vhost].ssl_cert[len] = '\0';
            }
            while (*p && *p != ';') p++;
            if (*p == ';') p++;
            continue;
        }
        
        // Match root
        if (strncmp(p, "root", 4) == 0) {
            p += 4;
            while (*p == ' ' || *p == '\t') p++;
            char *start = p;
            while (*p && *p != ';' && *p != ' ' && *p != '\n' && *p != '\r') p++;
            int path_len = p - start;
            if (path_len > 0 && path_len < 255) {
                if (current_vhost >= 0) {
                    memcpy(vhosts[current_vhost].doc_root, start, path_len);
                    if (vhosts[current_vhost].doc_root[path_len-1] != '/') {
                        vhosts[current_vhost].doc_root[path_len] = '/';
                    }
                }
                // Fallback / Default Doc Root
                for (int i=0; i<256; i++) doc_root[i] = '\0'; // clear
                memcpy(doc_root, start, path_len);
                if (doc_root[path_len-1] != '/') {
                    doc_root[path_len] = '/'; // Must end with slash
                }
            }
            while (*p && *p != ';') p++;
            if (*p == ';') p++;
            continue;
        }

        // Match index
        if (strncmp(p, "index", 5) == 0 && (p[5] == ' ' || p[5] == '\t')) {
            p += 5;
            if (current_vhost >= 0) {
                vhosts[current_vhost].index_count = 0;
            }
            while (*p && *p != ';') {
                while (*p == ' ' || *p == '\t') p++;
                if (*p == ';' || *p == '\n' || *p == '\r' || !*p) break;
                char *start = p;
                while (*p && *p != ' ' && *p != '\t' && *p != ';' && *p != '\n' && *p != '\r') p++;
                int len = p - start;
                if (current_vhost >= 0 && vhosts[current_vhost].index_count < 4 && len > 0 && len < 23) {
                    int i_idx = vhosts[current_vhost].index_count;
                    memcpy(vhosts[current_vhost].index_files[i_idx], start, len);
                    vhosts[current_vhost].index_files[i_idx][len] = '\0';
                    vhosts[current_vhost].index_count++;
                }
            }
            if (*p == ';') p++;
            continue;
        }
        
        // Match shiny_modules (custom proxying settings to avoid regexes)
        if (strncmp(p, "shiny_uring", 11) == 0) {
            p += 11;
            while (*p == ' ' || *p == '\t') p++;
            if (strncmp(p, "on", 2) == 0) uring_enabled = 1;
            else if (strncmp(p, "off", 3) == 0) uring_enabled = 0;
            while (*p && *p != ';') p++;
            if (*p == ';') p++;
            continue;
        }

        if (strncmp(p, "shiny_xdp", 9) == 0) {
            p += 9;
            while (*p == ' ' || *p == '\t') p++;
            if (strncmp(p, "on", 2) == 0) xdp_enabled = 1;
            else if (strncmp(p, "off", 3) == 0) xdp_enabled = 0;
            while (*p && *p != ';') p++;
            if (*p == ';') p++;
            continue;
        }

        // Match proxy_pool_size
        if (strncmp(p, "proxy_pool_size", 15) == 0) {
            p += 15;
            while (*p == ' ' || *p == '\t') p++;
            int val = my_atoi(p);
            if (val > 0 && val <= 256) proxy_pool_size_global = val;
            while (*p && *p != ';') p++;
            if (*p == ';') p++;
            continue;
        }

        // Match location block (inside a server)
        if (strncmp(p, "location", 8) == 0 && (p[8] == ' ' || p[8] == '\t')) {
            p += 8;
            while (*p == ' ' || *p == '\t') p++;
            char *start = p;
            while (*p && *p != ' ' && *p != '{' && *p != '\n' && *p != '\r') p++;
            int path_len = p - start;
            if (current_vhost >= 0 && vhosts[current_vhost].loc_count < 4 && path_len > 0 && path_len < 31) {
                int lidx = vhosts[current_vhost].loc_count;
                memcpy(vhosts[current_vhost].locs[lidx].path, start, path_len);
                vhosts[current_vhost].locs[lidx].path[path_len] = '\0';
                vhosts[current_vhost].loc_count++;
            }
            while (*p && *p != '{') p++;
            if (*p == '{') p++;
            continue;
        }

        // Match proxy_pass
        if (strncmp(p, "proxy_pass", 10) == 0 && (p[10] == ' ' || p[10] == '\t')) {
            p += 10;
            while (*p == ' ' || *p == '\t') p++;
            char *start = p;
            while (*p && *p != ';') p++;
            int pass_len = p - start;
            if (current_vhost >= 0 && vhosts[current_vhost].loc_count > 0 && pass_len > 0 && pass_len < 127) {
                int lidx = vhosts[current_vhost].loc_count - 1;
                // Parse "unix:/path"
                char *unix_ptr = start;
                while (unix_ptr < p - 5) {
                    if (strncmp(unix_ptr, "unix:", 5) == 0) {
                        unix_ptr += 5;
                        int sock_len = p - unix_ptr;
                        if (sock_len > 0 && sock_len < 105) {
                            vhosts[current_vhost].locs[lidx].proxy_family = AF_UNIX;
                            memcpy(vhosts[current_vhost].locs[lidx].proxy_addr, unix_ptr, sock_len);
                            vhosts[current_vhost].locs[lidx].proxy_addr[sock_len] = '\0';
                            
                            vhosts[current_vhost].locs[lidx].is_proxy = 1;
                            // Splice is natively unsupported for AF_UNIX sockets (Kernel returns -EINVAL).
                            vhosts[current_vhost].locs[lidx].splice_mode = 0; 
                        }
                        break;
                    } else if (strncmp(unix_ptr, "http://", 7) == 0) {
                        unix_ptr += 7;
                        int name_len = 0;
                        while (unix_ptr[name_len] && unix_ptr[name_len] != ';' && unix_ptr[name_len] != '/' && unix_ptr[name_len] != ' ' && unix_ptr[name_len] != '\n') name_len++;
                        
                        // Find matching upstream globally
                        int matched_upstream = -1;
                        for (int uid = 0; uid < upstreams_count; uid++) {
                            if ((int)strlen(upstreams_list[uid].name) == name_len && strncmp(upstreams_list[uid].name, unix_ptr, name_len) == 0) {
                                matched_upstream = uid;
                                break;
                            }
                        }

                        if (matched_upstream >= 0) {
                            memset(&vhosts[current_vhost].locs[lidx].proxy_family, 0, 108);
                            vhosts[current_vhost].locs[lidx].proxy_family = 0xFF; // Magic Upstream Flag
                            vhosts[current_vhost].locs[lidx].proxy_addr[0] = (char)matched_upstream;
                            vhosts[current_vhost].locs[lidx].is_proxy = 1;
                            vhosts[current_vhost].locs[lidx].splice_mode = 0; // Handled dynamically in ASM
                        } else {
                            // Legacy single fallback (Direct IP:PORT)
                            char temp_ip[64] = {0};
                            memcpy(temp_ip, unix_ptr, name_len);
                            char *colon = strchr(temp_ip, ':');
                            int port = 80;
                            if (colon) {
                                *colon = '\0';
                                port = atoi(colon + 1);
                            }
                            struct sockaddr_in in_addr;
                            memset(&in_addr, 0, sizeof(struct sockaddr_in));
                            in_addr.sin_family = AF_INET;
                            in_addr.sin_port = htons(port);
                            inet_pton(AF_INET, temp_ip, &in_addr.sin_addr);

                            memset(&vhosts[current_vhost].locs[lidx].proxy_family, 0, 108);
                            vhosts[current_vhost].locs[lidx].proxy_family = AF_INET;
                            memcpy(vhosts[current_vhost].locs[lidx].proxy_addr, &in_addr.sin_port, 14);
                            
                            vhosts[current_vhost].locs[lidx].is_proxy = 1;
                            vhosts[current_vhost].locs[lidx].splice_mode = 1; // Only for AF_INET
                        }
                        break;
                    }
                    unix_ptr++;
                }
            }
            if (*p == ';') p++;
            continue;
        }

        // Match server unix: or tcp (inside upstream)
        if (strncmp(p, "server", 6) == 0 && (p[6] == ' ' || p[6] == '\t')) {
            char *tmpp = p + 6;
            while (*tmpp == ' ' || *tmpp == '\t') tmpp++;
            if (*tmpp != '{' && current_upstream >= 0 && upstreams_list[current_upstream].server_count < 16) {
                int sidx = upstreams_list[current_upstream].server_count;
                if (strncmp(tmpp, "unix:", 5) == 0) {
                    tmpp += 5;
                    int sock_len = 0;
                    while (tmpp[sock_len] && tmpp[sock_len] != ';' && tmpp[sock_len] != ' ' && tmpp[sock_len] != '\n') sock_len++;
                    if (sock_len > 0 && sock_len < 105) {
                        struct sockaddr_un un_addr;
                        memset(&un_addr, 0, sizeof(struct sockaddr_un));
                        un_addr.sun_family = AF_UNIX;
                        memcpy(un_addr.sun_path, tmpp, sock_len);
                        un_addr.sun_path[sock_len] = '\0';
                        upstreams_list[current_upstream].families[sidx] = AF_UNIX;
                        memcpy(upstreams_list[current_upstream].addrs[sidx], un_addr.sun_path, 106);
                        upstreams_list[current_upstream].server_count++;
                    }
                    p = tmpp + sock_len;
                    while (*p && *p != ';') p++;
                    if (*p == ';') p++;
                    continue;
                } else {
                    int sock_len = 0;
                    while (tmpp[sock_len] && tmpp[sock_len] != ';' && tmpp[sock_len] != ' ' && tmpp[sock_len] != '\n') sock_len++;
                    if (sock_len > 0 && sock_len < 63) {
                        char temp_ip[64] = {0};
                        memcpy(temp_ip, tmpp, sock_len);
                        char *colon = strchr(temp_ip, ':');
                        int port = 80;
                        if (colon) {
                            *colon = '\0';
                            port = atoi(colon + 1);
                        }
                        struct sockaddr_in in_addr;
                        memset(&in_addr, 0, sizeof(struct sockaddr_in));
                        in_addr.sin_family = AF_INET;
                        in_addr.sin_port = htons(port);
                        inet_pton(AF_INET, temp_ip, &in_addr.sin_addr);
                        upstreams_list[current_upstream].families[sidx] = AF_INET;
                        memcpy(upstreams_list[current_upstream].addrs[sidx], &in_addr.sin_port, 14); // Note: sockaddr_in payload is 14 bytes after family
                        upstreams_list[current_upstream].server_count++;
                    }
                    p = tmpp + sock_len;
                    while (*p && *p != ';') p++;
                    if (*p == ';') p++;
                    continue;
                }
            }
        }

        // Just advance if we don't recognize it or it's 'http' / 'server' / 'location'
        // For simplistic parsing, we just skip words we don't know
        while (*p && *p != ' ' && *p != '\n' && *p != '\r' && *p != '{' && *p != '}' && *p != ';') p++;
        if (*p == ';') p++;
    }

    if (vhost_count_global == 0) {
        vhost_count_global = 1;
        strcpy(vhosts[0].domain, "default");
        strcpy(vhosts[0].doc_root, doc_root);
    }
}
