; ==============================================================================
; Advanced HTTP Web Server in x86_64 Assembler (Linux Ubuntu 24.04)
; “Apache-like” features:
; - Serves files from a root folder (./www/)
; - Uses sys_sendfile for maximum performance (Zero-Copy)
; - Handles 404 (Not Found) errors
; - Detects extension (.css vs .html)
; ==============================================================================

PROXY_POOL_CAP equ 256         ; Max pool array size (BSS). Runtime size from proxy_pool_size_global.

section .data
    global doc_root
    global xdp_enabled
    global tls_enabled
    global zc_enabled
    global uring_enabled
    global worker_count_global
    global proxy_pool_size_global
    global vhost_count_global
    global vhosts
    global access_log_enabled
    global tcp_nopush_enabled
    global tcp_nodelay_enabled
    global reuseport_enabled
    extern upstreams_list
    global worker_connections_global
    global proxy_http_version_1_1
    global proxy_set_keepalive

    doc_root db "./www/", 0
    times 248 db 0      ; Reserve space for dynamically injected path
    index_file db "index.html", 0
    index_path db "./www/index.html", 0
    debug_file db "./www/debug.txt", 0

    ; Dynamic directory scanner will now populate cache

    ; --- En-têtes HTTP Keep-Alive ---
    hdr_ka_html db "HTTP/1.1 200 OK", 13, 10
                db "Server: Shiny", 13, 10
                db "Connection: keep-alive", 13, 10
                db "Content-Type: text/html; charset=UTF-8", 13, 10
                db "Content-Length: "
    hdr_ka_html_len equ $ - hdr_ka_html

    hdr_base db "HTTP/1.1 200 OK", 13, 10
             db "Server: Shiny", 13, 10
             db "Connection: keep-alive", 13, 10
             db "Content-Type: "
    hdr_base_len equ $ - hdr_base

    hdr_cl_str db 13, 10, "Content-Length: "
    hdr_cl_str_len equ $ - hdr_cl_str
    
    default_mime_str db "application/octet-stream", 0

    hdr_ka_css db "HTTP/1.1 200 OK", 13, 10
               db "Server: Shiny", 13, 10
               db "Connection: keep-alive", 13, 10
               db "Content-Type: text/css", 13, 10
               db "Content-Length: "
    hdr_ka_css_len equ $ - hdr_ka_css

    hdr_cl_end db 13, 10, 13, 10
    hdr_cl_end_len equ $ - hdr_cl_end

    hdr_ka_json db "HTTP/1.1 200 OK", 13, 10
                db "Server: Shiny", 13, 10
                db "Connection: keep-alive", 13, 10
                db "Content-Type: application/json", 13, 10
                db "Content-Length: "
    hdr_ka_json_len equ $ - hdr_ka_json

    hdr_206 db "HTTP/1.1 206 Partial Content", 13, 10, "Content-Type: video/mp4", 13, 10, "Connection: keep-alive", 13, 10, "Content-Length: "
    hdr_206_len equ $ - hdr_206
    
    hdr_416 db "HTTP/1.1 416 Range Not Satisfiable", 13, 10, "Connection: close", 13, 10, 13, 10
    hdr_416_len equ $ - hdr_416

    str_cr_bytes db 13, 10, "Content-Range: bytes "
    str_cr_bytes_len equ $ - str_cr_bytes

    msg_auth_ok db "HTTP/1.1 200 OK", 13, 10
            db "Server: Shiny", 13, 10
            db "Content-Type: application/json", 13, 10
            db "Connection: keep-alive", 13, 10
            db "Content-Length: 646", 13, 10, 13, 10
            db '{"status":"ok","token":"eyJhbGciOiJIUzI1NiJ9"}'
            times 600 db ' '
    msg_auth_ok_len equ $ - msg_auth_ok

    msg_304 db "HTTP/1.1 304 Not Modified", 13, 10, "Connection: keep-alive", 13, 10, 13, 10
    msg_304_len equ $ - msg_304

    msg_fixedfiles_ok db "[INFO] IO_URING Fixed Files : Listening socket enregistre.", 13, 10
    msg_fixedfiles_ok_len equ $ - msg_fixedfiles_ok

    msg_async_send_ok db "[INFO] IO_URING Async SEND : Reponses non-bloquantes via SQE.", 13, 10
    msg_async_send_ok_len equ $ - msg_async_send_ok

    msg_tls_ok db "[INFO] TLS 1.3 actif : Chiffrement kTLS kernel (AES-128-GCM, EC P-256).", 13, 10
    msg_tls_ok_len equ $ - msg_tls_ok

    msg_tls_fail db "[WARN] TLS 1.3 echec : Certificat ou kTLS non disponible. HTTP seul.", 13, 10
    msg_tls_fail_len equ $ - msg_tls_fail

    tls_cert_path db "/app/server.crt", 0
    tls_key_path db "/app/server.key", 0

    hdr_ka_txt db "HTTP/1.1 200 OK", 13, 10
               db "Server: Shiny", 13, 10
               db "Connection: keep-alive", 13, 10
               db "Content-Type: text/plain", 13, 10
               db "Content-Length: "
    hdr_ka_txt_len equ $ - hdr_ka_txt

    hdr_404 db "HTTP/1.1 404 Not Found", 13, 10
            db "Server: Shiny", 13, 10
            db "Connection: close", 13, 10
            db "Content-Type: text/html; charset=UTF-8", 13, 10, 13, 10
            db "<h1>404 - Fichier introuvable</h1>"
    hdr_404_len equ $ - hdr_404

    hdr_405 db "HTTP/1.1 405 Method Not Allowed", 13, 10
            db "Server: Shiny", 13, 10
            db "Connection: close", 13, 10
            db "Allow: GET", 13, 10
            db "Content-Length: 0", 13, 10, 13, 10
    hdr_405_len equ $ - hdr_405

    msg_502 db "HTTP/1.1 502 Bad Gateway", 13, 10
            db "Connection: close", 13, 10
            db "Content-Length: 15", 13, 10, 13, 10
            db "502 Bad Gateway"
    msg_502_len equ $ - msg_502

    msg_503 db "HTTP/1.1 503 Service Unavailable", 13, 10
            db "Connection: close", 13, 10
            db "Content-Length: 24", 13, 10, 13, 10
            db "503 Service Unavailable"
    msg_503_len equ $ - msg_503

    cork_on  dd 1
    cork_off dd 0

    global sockaddr_port
    ; --- Structure sockaddr_in ---
    sockaddr dw 2           ; AF_INET
    sockaddr_port dw 0x901f      ; Port 8080
             dd 0           ; INADDR_ANY
             dq 0

    optval dd 1             ; For SO_REUSEADDR

    ; Keep-alive timeout: 5 seconds
    ka_timeout dq 5          ; tv_sec = 5
               dq 0          ; tv_usec = 0
    conf_file db "server.conf", 0
    routes_conf db "routes.conf", 0
    http_suffix db " HTTP/1.1", 13, 10

    ; sigaction structure to ignore SIGPIPE
    ign_sigaction:
        dq 1                ; sa_handler = SIG_IGN (1)
        dq 0                ; sa_flags
        dq 0                ; sa_restorer
        dq 0                ; sa_mask

    msg_avx_ok db "[INFO] AVX-512 detecte : Acceleration Materielle du Parsing HTTP ACTIVE", 13, 10
    msg_avx_ok_len equ $ - msg_avx_ok

    msg_avx2_ok db "[INFO] AVX2 detecte : Acceleration Materielle du Parsing HTTP ACTIVE (32 octets)", 13, 10
    msg_avx2_ok_len equ $ - msg_avx2_ok

    msg_bind_err db "[FATAL] Bind EADDRINUSE !", 10
    msg_accept_err db "[FATAL] accept4 failed (ENOTSOCK?)", 10
    msg_proxy_err db "[WARN] Backend Proxy ferme", 10
    msg_none_ko db "[WARN] Aucun AVX detecte : Parsing HTTP standard (sans acceleration)", 13, 10
    msg_none_ko_len equ $ - msg_none_ko

    ; --- UDS Proxy Data ---
    conf_d_path db "./conf.d", 0
    
    msg_xdp_ok db "[INFO] AF_XDP actif : Court-circuitage TCP/IP etabli (Raw Ethernet). Transfert vers Mode Standard...", 13, 10
    msg_xdp_ok_len equ $ - msg_xdp_ok

    msg_xdp_ko db "[WARN] AF_XDP echec (droits root/support requis). Fallback sur TCP/IP Linux standard.", 13, 10
    msg_xdp_ko_len equ $ - msg_xdp_ko

    access_log_path db "access.log", 0
    msg_log_write db "127.0.0.1 - - [2026-03-30 19:00:00] GET / HTTP/1.1 200 OK", 10
    msg_log_write_len equ $ - msg_log_write

    msg_uring_ok db "[INFO] IO_URING actif : Ring Buffers montes avec succes !", 13, 10
    msg_uring_ok_len equ $ - msg_uring_ok

    msg_sqpoll_ok db "[INFO] IO_URING SQPOLL actif : Kernel thread dedie, ZERO syscall !", 13, 10
    msg_sqpoll_ok_len equ $ - msg_sqpoll_ok

    msg_regbuf_ok db "[INFO] IO_URING Registered Buffers : 64 buffers epingles dans le noyau.", 13, 10
    msg_regbuf_ok_len equ $ - msg_regbuf_ok

    msg_multishot_ok db "[INFO] IO_URING Multi-shot Accept : Un seul SQE pour toutes les connexions.", 13, 10
    msg_multishot_ok_len equ $ - msg_multishot_ok

    msg_pool_ok db "[INFO] Proxy Pool : Connexions persistantes pre-connectees au backend.", 13, 10
    msg_pool_ok_len equ $ - msg_pool_ok

    msg_tfo_ok db "[INFO] TCP_FASTOPEN actif : Clients recurrents evitent le 3-way handshake.", 13, 10
    msg_tfo_ok_len equ $ - msg_tfo_ok

    ; TCP_FASTOPEN queue length
    tfo_qlen dd 256

    msg_xdp_umem_ok db "[INFO] AF_XDP: UMEM (2MB) + Rings montes. Fast-path actif !", 13, 10
    msg_xdp_umem_ok_len equ $ - msg_xdp_umem_ok

    msg_xdp_bpf_ok db "[INFO] AF_XDP: Programme BPF charge et attache a l'interface.", 13, 10
    msg_xdp_bpf_ok_len equ $ - msg_xdp_bpf_ok

    ; XDP BPF program path
    xdp_bpf_path db "xdp_redirect.bpf.o", 0

    ; Network interface name for XDP bind
    xdp_ifname db "eth0", 0

    ; XDP UMEM registration struct (struct xdp_umem_reg)
    ; { addr, len, chunk_size, headroom, flags }
    xdp_umem_reg:
        xdp_umem_addr dq 0      ; filled at runtime
        xdp_umem_len  dq 2 * 1024 * 1024  ; 2MB
        xdp_chunk_sz  dd 4096   ; frame size
        xdp_headroom  dd 0
        xdp_umem_flg  dd 0

    ; SOL_XDP = 283
    ; XDP_UMEM_REG = 4, XDP_UMEM_FILL_RING = 5, XDP_UMEM_COMPLETION_RING = 6
    ; XDP_RX_RING = 1, XDP_TX_RING = 2
    xdp_ring_size dd 512      ; ring size for all rings

    ; struct sockaddr_xdp for bind
    xdp_sa:
        xdp_sa_family dw 44     ; AF_XDP
        xdp_sa_flags  dw 0
        xdp_sa_ifidx  dd 0      ; filled at runtime
        xdp_sa_qid    dd 0      ; tail 0
        xdp_sa_shumem dd 0      ; shared UMEM group

    msg_cores db "[INFO] Auto-detect CPU: "
    msg_cores_len equ $ - msg_cores
    msg_workers db " cores disponibles", 13, 10
    msg_workers_len equ $ - msg_workers

    default_log_fmt db "[REQ] %m %u", 0
    log_file_name db "access.log", 0

    ; Characters to look for in AVX-512 / AVX2
    char_space db 0x20
    char_qmark db 0x3F
    char_cr    db 13
    char_lf    db 10
    char_nul   db 0

    default_conf_file db "shiny.conf", 0

section .bss
    align 8
    config_file_ptr resq 1
    worker_count_global resd 1
    proxy_pool_size_global resd 1
    vhost_count_global resd 1
    tcp_nopush_enabled resb 1
    tcp_nodelay_enabled resb 1
    reuseport_enabled resb 1
    worker_connections_global resd 1
    proxy_http_version_1_1 resb 1
    proxy_set_keepalive resb 1
    vhosts resb 32768
    listen_fds resd 16
    bound_ports resw 16
    listen_count resd 1
    client_sock resq 1
    file_fd resq 1
    alignb 8
    route_jump_table resq 256
    jit_memory_ptr resq 1
    routing_enabled resb 1
    avx512_enabled resb 1
    avx2_enabled resb 1
    ; proxy_entries removed
    conf_dir_fd resd 1
    xdp_enabled resb 1
    tls_enabled resb 1
    handshake_out_buf resb 4108
    zc_enabled resb 1
    uring_enabled resb 1
    uring_fd resd 1
    sq_ring resq 1
    cq_ring resq 1
    sqes resq 1
    uring_params resb 120
    cqe_saved_head resd 1
    cqe_saved_tail resd 1
    cqe_batch_count resd 1
    ; BSS State Arrays for Socket Overflow Chunking & Async Sendfile
    slot_mem_ptr resq 65536
    slot_mem_remaining resq 65536
    slot_file_fd resq 65536
    slot_file_remaining resq 65536
    slot_file_offset resq 65536
    slot_range_offset resq 65536
    slot_range_end resq 65536
    slot_log_buf resb 16777216 ; 65536 * 256 bytes for async access logs
    slot_206_hdr resb 16777216 ; 65536 * 256 bytes
    client_addr resb 16
    client_addr_len resd 1
    slot_pipeline_end_buf resq 200000
    slot_pipeline_next_req resq 200000
    alignb 32
    buffer resb 4096
    filepath resb 1024
    filepath_root_end resq 1
    alignb 32
    resp_hdr resb 512
    itoa_buf resb 24
    conn_pool resq 1
    slot_fds resd 65536
    slot_listen_fds resd 65536
    slot_proxy_fds resd 65536
    slot_proxy_lb_meta resw 65536
    slot_proxy_state resb 65536
    slot_proxy_te_close resb 65536   ; Flag: force close after TE:chunked response (anti-smuggling)
    slot_proxy_req_len resd 65536
    slot_proxy_resp_total resd 65536
    slot_proxy_resp_received resd 65536
    slot_proxy_req_ptr resq 65536
    slot_proxy_pipe_len resd 65536
    slot_proxy_sockaddr resb 7208960 ; 65536 * 110 bytes
    slot_proxy_pipe_r resd 65536
    slot_proxy_pipe_w resd 65536
    ; --- Proxy Connection Pool (Multifaceted Hash-Map per Route) ---
    proxy_pool_stacks resd 65536          ; [route_id][256] = 256 routes * 256 fds
    proxy_pool_tops   resd 256            ; top indices for each route (0 to 255)
    slot_proxy_loc_idx resd 65536         ; tracks which route the slot matched
    proxy_pool_addr  resb 110             ; cached proxy sockaddr
    proxy_pool_addrlen resd 1             ; cached addrlen
    slot_free resd 65536
    slot_top resd 1
    cur_slot resd 1
    slot_vhost_id resd 65536
    slot_method resb 65536
    ; Multi-file cache hash table: 1024 entries × 64 bytes
    cache_table resb 1024 * 64
    cache_pool resq 1
    cache_pool_ptr resq 1
    cache_scan_buf resb 4096
    cof_docroot_len resq 1
    legacy_client_fd resq 1
    shutdown_flag resb 1
    reload_flag resb 1
    sqpoll_active resb 1
    alignb 16
    reg_iov_array resb 256 * 16       ; 256 × struct iovec {ptr, len}
    log_buf resb 256
    log_format_string resb 128
    access_log_enabled resb 1
    access_log_type resb 1
    log_fd resq 1
    cpu_count resd 1
    unix_time resq 1
    ; AF_XDP state
    xsk_fd resd 1                    ; AF_XDP socket fd
    xdp_umem_ptr resq 1              ; UMEM base address
    xdp_fill_ring resq 1             ; FILL ring mmap ptr
    xdp_comp_ring resq 1             ; COMPLETION ring mmap ptr
    xdp_rx_ring resq 1               ; RX ring mmap ptr
    xdp_tx_ring resq 1               ; TX ring mmap ptr
    xdp_fill_prod resd 1             ; FILL producer index
    xdp_tx_prod resd 1               ; TX producer index
    xdp_rx_cons resd 1               ; RX consumer index
    xdp_comp_cons resd 1             ; COMPLETION consumer index
    xdp_ifindex resd 1               ; network interface index
    xdp_bpf_fd resd 1                ; BPF program fd
    xdp_map_fd resd 1                ; XSKMAP fd
    ; Raw TCP state per connection
    xdp_tcp_seq resd 1               ; our sequence number
    xdp_tcp_ack resd 1               ; their sequence number
    ; Pre-built response packet template (Eth+IP+TCP+HTTP)
    alignb 64
    xdp_pkt_buf resb 1500            ; single packet build area
    ; Fixed file table for IORING_REGISTER_FILES
    alignb 8
    fixed_fds resd 16
    ; Per-slot send state: buffer ptr + length for async SEND completion
    send_buf_ptr resq 65536          ; saved buffer ptr per slot
    send_buf_len resd 65536          ; saved buffer lens per slot
    alignb 32
    stat_buf resb 256

section .text
    global _start
    ; External variables from C
    extern mime_dict
    extern mime_count_global
    extern tls_ctx_init
    extern tls_worker_init
    extern tls_req_fd
    extern tls_res_fd
    extern port_is_ssl

_start:
    ; --- Parse CLI args ---
    mov rax, [rsp]          ; argc
    cmp rax, 2
    jl .no_args
    mov rdi, [rsp + 16]     ; argv[1]
    mov [config_file_ptr], rdi
    jmp .args_done
.no_args:
    mov rdi, default_conf_file
    mov [config_file_ptr], rdi
.args_done:

    ; --- IGNORER SIGPIPE ---
    mov rax, 13
    mov rdi, 13
    mov rsi, ign_sigaction
    mov rdx, 0
    mov r10, 8
    syscall

    ; --- SIGTERM: graceful shutdown ---
    ; Set handler to sigterm_handler
    sub rsp, 32
    mov qword [rsp], sigterm_handler  ; sa_handler
    mov qword [rsp + 8], 0x04000000   ; sa_flags = SA_RESTORER (not needed, just flags)
    mov qword [rsp + 16], 0           ; sa_restorer
    mov qword [rsp + 24], 0           ; sa_mask
    mov rax, 13             ; rt_sigaction
    mov rdi, 15             ; SIGTERM
    mov rsi, rsp
    mov rdx, 0
    mov r10, 8
    syscall
    add rsp, 32
    mov byte [shutdown_flag], 0

    ; --- SIGHUP: cache reload ---
    sub rsp, 32
    mov qword [rsp], sighup_handler
    mov qword [rsp + 8], 0x04000000
    mov qword [rsp + 16], 0
    mov qword [rsp + 24], 0
    mov rax, 13
    mov rdi, 1              ; SIGHUP
    mov rsi, rsp
    mov rdx, 0
    mov r10, 8
    syscall
    add rsp, 32
    mov byte [reload_flag], 0

    ; --- VERIFICATION AVX-512 ---
    push rbx
    mov eax, 7
    xor ecx, ecx
    cpuid
    ; AVX512F = bit 16 de ebx, AVX512BW = bit 30 de ebx
    mov eax, ebx
    and eax, (1<<16) | (1<<30)
    cmp eax, (1<<16) | (1<<30)
    jne .no_avx512

    ; Supported AVX-512
    mov byte [avx512_enabled], 1
    mov byte [avx2_enabled], 0
    mov rax, 1        ; sys_write
    mov rdi, 1        ; stdout
    mov rsi, msg_avx_ok
    mov rdx, msg_avx_ok_len
    syscall
    jmp .avx_done

.no_avx512:
    mov byte [avx512_enabled], 0

    ; AVX2 = bit 5 de ebx
    test ebx, (1<<5)
    jz .no_avx2

    ; AVX2 supported
    mov byte [avx2_enabled], 1
    mov rax, 1
    mov rdi, 1
    mov rsi, msg_avx2_ok
    mov rdx, msg_avx2_ok_len
    syscall
    jmp .avx_done

.no_avx2:
    mov byte [avx2_enabled], 0
    mov rax, 1
    mov rdi, 1
    lea rsi, [msg_bind_err]
    mov rdx, 29
    syscall

.avx_done:
    pop rbx

    ; --- AUTO-DETECT CPU CORES ---
    sub rsp, 128
    mov rax, 204             ; sched_getaffinity
    xor rdi, rdi             ; pid = 0 (self)
    mov rsi, 128
    mov rdx, rsp
    syscall
    cmp rax, 0
    jl .use_default_cores
    ; Count set bits in affinity mask (first 8 bytes usually enough)
    mov rax, [rsp]
    popcnt rax, rax
    cmp rax, 0
    jle .use_default_cores
    mov r14, rax
    mov [cpu_count], eax
    add rsp, 128

    ; Log detected cores
    push r14
    mov rax, 1
    mov rdi, 1
    mov rsi, msg_cores
    mov rdx, msg_cores_len
    syscall
    ; Print number
    pop r14
    push r14
    mov rax, r14
    lea r8, [itoa_buf + 20]
    mov byte [r8], 0
    mov rcx, 0xCCCCCCCCCCCCCCCD
.cores_itoa:
    dec r8
    mov r9, rax
    mul rcx
    shr rdx, 3
    lea r10, [rdx + rdx*4]
    add r10, r10
    sub r9, r10
    add r9b, '0'
    mov [r8], r9b
    mov rax, rdx
    test rax, rax
    jnz .cores_itoa
    ; Find length
    lea rsi, [itoa_buf + 20]
    mov rdx, rsi
    sub rdx, r8
    mov rsi, r8
    mov rax, 1
    mov rdi, 1
    syscall
    mov rax, 1
    mov rdi, 1
    mov rsi, msg_workers
    mov rdx, msg_workers_len
    syscall
    pop r14
    jmp .cores_done

.use_default_cores:
    add rsp, 128
    mov r14, 4
.cores_done:

    ; --- LECTURE CONFIGURATION NGINX-STYLE ---
    ; Call the C parser (nginx_parser.c)
    mov rdi, [config_file_ptr]
    extern parse_nginx_config
    call parse_nginx_config

    ; Override auto-detected CPU cores if worker_processes is explicitly set
    mov eax, dword [worker_count_global]
    test eax, eax
    jz .skip_config
    mov r14d, eax        ; Number of workers overridden by shiny.conf

.skip_config:
    ; Config is now parsed by nginx_parser.c
    ; Provide safe defaults for variables not yet handled by C parser
    
    ; Initialize log_format_string with default
    mov rsi, default_log_fmt
    mov rdi, log_format_string
    mov rcx, 12
    rep movsb

    ; Default to stdout if no log type set
    mov qword [log_fd], 1
    
    ; Open access.log if LOG=2 (handled by future C parser addition, manual override here)
    cmp byte [access_log_type], 2
    jne .skip_open_log
    mov rax, 2                      ; sys_open
    mov rdi, log_file_name
    mov rsi, 1089                   ; O_WRONLY(1) | O_CREAT(64) | O_APPEND(1024)
    mov rdx, 420                    ; 0644 permissions (octal 644 -> dec 420)
    syscall
    cmp rax, 0
    jl .skip_open_log               ; Fallback safely
    mov [log_fd], rax
.skip_open_log:


    ; ---------- NO MORE CONF.D PARSER ----------
    ; Reverse Proxies are now resolved dynamically native Nginx style locations!


    ; --- ZERO OVERHEAD ROUTING: JIT INIT ---
    ; Initialize Jump Table with normal_routing
    mov rcx, 256
    lea rdi, [route_jump_table]
    lea r8, [normal_routing]
.init_jt:
    mov [rdi], r8
    add rdi, 8
    loop .init_jt

    ; Allocate executable memory (sys_mmap)
    mov rax, 9                  ; sys_mmap
    xor rdi, rdi                ; addr = NULL
    mov rsi, 65536              ; length = 64KB
    mov rdx, 7                  ; prot = PROT_READ | PROT_WRITE | PROT_EXEC
    mov r10, 98                 ; flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT
    mov r8, -1                  ; fd = -1
    xor r9, r9                  ; offset = 0
    syscall
    test rax, rax
    js .skip_jit
    mov [jit_memory_ptr], rax

    ; Read routes.conf into buffer
    mov rax, 2                  ; sys_open
    mov rdi, routes_conf
    mov rsi, 0                  ; O_RDONLY
    xor rdx, rdx
    syscall
    test rax, rax
    js .skip_jit
    mov r12, rax                ; fd

    mov rax, 0                  ; sys_read
    mov rdi, r12
    mov rsi, buffer
    mov rdx, 4096
    syscall
    mov r13, rax                ; bytes read

    mov rax, 3                  ; sys_close
    mov rdi, r12
    syscall

    test r13, r13
    jle .skip_jit
    mov byte [routing_enabled], 1

    ; JIT Compilation Loop
    mov rsi, buffer
    mov r8, buffer
    add r8, r13
    mov r13, r8                 ; r13 = end of buffer
    mov r15, [jit_memory_ptr]

.parse_routes:
    cmp rsi, r13
    jge .skip_jit

    mov rdi, rsi
.find_nl:
    cmp rdi, r13
    jge .process_route
    cmp byte [rdi], 10
    je .process_route
    inc rdi
    jmp .find_nl

.process_route:
    mov rcx, rdi
    sub rcx, rsi
    cmp rcx, 0
    jle .next_route

    sub rsp, 32
    pxor xmm0, xmm0
    movdqu [rsp], xmm0
    movdqu [rsp+16], xmm0

    mov r8, 0
.copy_rte:
    cmp r8, rcx
    jge .pad_http
    cmp r8, 16
    jge .pad_http
    mov al, [rsi+r8]
    mov [rsp+r8], al
    inc r8
    jmp .copy_rte

.pad_http:
    lea r9, [http_suffix]
    mov r10, 0
.copy_pad:
    cmp r8, 16
    jge .hash_route
    mov al, [r9+r10]
    mov [rsp+r8], al
    inc r8
    inc r10
    jmp .copy_pad

.hash_route:
    mov r8, [rsp]
    mov r9, [rsp+8]
    
    xor rax, rax
    crc32 rax, r8
    crc32 rax, r9
    and rax, 0xFF

    lea r10, [route_jump_table]
    mov [r10 + rax*8], r15

    ; Compile: mov r8, expected1 (49 B8 [8 bytes])
    mov word [r15], 0xB849
    add r15, 2
    mov [r15], r8
    add r15, 8

    ; Compile: cmp rax, r8 (4C 39 C0)
    ; 0xC0394C encoded in little-endian taking 3 bytes
    mov byte [r15], 0x4C
    mov byte [r15+1], 0x39
    mov byte [r15+2], 0xC0
    add r15, 3

    ; Compile: jne normal_routing (0F 85 [4 bytes])
    mov word [r15], 0x850F
    add r15, 2
    lea r10, [normal_routing]
    mov r11, r10
    sub r11, r15
    sub r11, 4
    mov [r15], r11d
    add r15, 4

    ; Compile: mov r8, expected2 (49 B8 [8 bytes])
    mov word [r15], 0xB849
    add r15, 2
    mov [r15], r9
    add r15, 8

    ; Compile: cmp rbx, r8 (4C 39 C3)
    mov byte [r15], 0x4C
    mov byte [r15+1], 0x39
    mov byte [r15+2], 0xC3
    add r15, 3

    ; Compile: jne normal_routing (0F 85 [4 bytes])
    mov word [r15], 0x850F
    add r15, 2
    lea r10, [normal_routing]
    mov r11, r10
    sub r11, r15
    sub r11, 4
    mov [r15], r11d
    add r15, 4

    ; String calculation addresses
    ; Jumps emit 24 bytes more (mov rdi, mov r14, jmp open_file)
    mov r10, r15
    add r10, 25                 ; r10 = target_path_addr

    ; Compile: mov rdi, target_path_addr (48 BF [8 bytes])
    mov word [r15], 0xBF48
    add r15, 2
    mov [r15], r10
    add r15, 8

    ; Compile: mov r14, r14_val_addr (49 BE [8 bytes])
    mov r11, r10
    add r11, 5                  ; len("./www")
    add r11, rcx                ; path_len
    mov word [r15], 0xBE49
    add r15, 2
    mov [r15], r11
    add r15, 8

    ; Compile: jmp open_file_with_rdi (E9 [4 bytes])
    mov byte [r15], 0xE9
    inc r15
    lea r9, [open_file_with_rdi]
    mov rax, r9
    sub rax, r15
    sub rax, 4
    mov [r15], eax
    add r15, 4

    ; Write string "./www" + route
    lea r9, [doc_root]
    mov r8, 5
.cp_dr:
    mov al, [r9]
    mov [r15], al
    inc r9
    inc r15
    dec r8
    jnz .cp_dr

    mov r8, 0
.cp_rte:
    cmp r8, rcx
    jge .done_rte
    mov al, [rsi+r8]
    mov [r15], al
    inc r15
    inc r8
    jmp .cp_rte
.done_rte:
    mov byte [r15], 0
    inc r15

    add rsp, 32

.next_route:
    lea rsi, [rdi+1]
    jmp .parse_routes

.skip_jit:
    ; --- W^X ENFORCEMENT: Downgrade JIT memory from RWX to RX (one-time startup cost) ---
    cmp qword [jit_memory_ptr], 0
    je .skip_mprotect
    mov rax, 10              ; sys_mprotect
    mov rdi, [jit_memory_ptr]
    mov rsi, 65536           ; length = 64KB
    mov rdx, 5               ; PROT_READ | PROT_EXEC (remove WRITE)
    syscall
.skip_mprotect:
    ; --- END ZERO OVERHEAD ROUTER SETUP ---
    ; --- FIN CONFIGURATION ---

    ; --- ACCESS LOG INITIALIZATION ---
    cmp byte [access_log_enabled], 1
    jne .skip_access_log
    
    mov rax, 2                  ; sys_open
    lea rdi, [access_log_path]
    mov rsi, 1089               ; O_WRONLY|O_CREAT|O_APPEND
    mov rdx, 420                ; 0644
    syscall
    test rax, rax
    js .skip_access_log
    mov qword [log_fd], rax

.skip_access_log:

    ; --- INIT GLOBAL TLS CONTEXT (BEFORE FORK) ---
    cmp byte [tls_enabled], 1
    jne .skip_tls_ctx_init
    call tls_ctx_init
.skip_tls_ctx_init:

    ; --- CREATION DES WORKERS (FORK FIRST) ---
.fork_loop:
    cmp r14, 1
    jle .worker_init ; Parent process becomes last worker
    
    mov rax, 57 ; sys_fork
    syscall
    cmp rax, 0
    je .worker_init ; The child leaves the orchestration loop
    
    ; The parent continues to fork
    dec r14
    jmp .fork_loop

.worker_init:
    ; --- TLS 1.3 INITIALIZATION (Per-Worker AFTER Fork) ---
    cmp byte [tls_enabled], 1
    jne .skip_tls_init
    ; Call tls_worker_init
    call tls_worker_init
    cmp eax, 0
    jl .tls_init_failed
    
    ; Log TLS success (Only worker 1 prints to avoid 8 spam logs)
    cmp r14, 1
    jne .skip_tls_init
    push r14
    mov rax, 1
    mov rdi, 1
    mov rsi, msg_tls_ok
    mov rdx, msg_tls_ok_len
    syscall
    pop r14
    jmp .skip_tls_init
.tls_init_failed:
    mov byte [tls_enabled], 0
    cmp r14, 1
    jne .skip_tls_init
    push r14
    mov rax, 1
    mov rdi, 1
    mov rsi, msg_tls_fail
    mov rdx, msg_tls_fail_len
    syscall
    pop r14
.skip_tls_init:

    ; --- DÉTERMINISME HYPER-STRICT (CPU PINNING) ---
    ; Isolate this worker on its exclusive logical Core (ID = r14)
    sub rsp, 128             ; Allocate cpu_set_t (128 bytes) on the stack

    ; Dynamically initializes the Memory Block to 0 (rep stosq)
    mov rcx, 16
    mov rdi, rsp
    xor rax, rax
    rep stosq

    ; Restores the pointer and sets the Mask bit (1 << r14)
    mov rdi, rsp
    mov cl, r14b
    mov rax, 1
    shl rax, cl              ; Bitshift to target the right Core
    mov [rdi], rax

    ; System Call: sched_setaffinity(PID=0, len=128, mask=rsp)
    mov rax, 203
    mov rdi, 0
    mov rsi, 128
    mov rdx, rsp
    syscall

    add rsp, 128             ; Clean memory

    ; Each Worker creates THEIR OWN XDP / INET socket and listens on the same port!
    ; --- 1. SOCKET (AF_XDP Bypass or Standard INET) ---
    cmp byte [xdp_enabled], 1
    jne .socket_inet
    
    ; ==============================================================
    ; AF_XDP FULL SETUP: UMEM, Rings, BPF Load, Socket Bind
    ; ==============================================================

    ; Step 1: Create AF_XDP socket
    mov rax, 41             ; sys_socket
    mov rdi, 44             ; AF_XDP
    mov rsi, 3              ; SOCK_RAW
    mov rdx, 0
    syscall
    cmp rax, 0
    jl .fallback_inet
    mov [xsk_fd], eax

    ; Step 2: Allocate UMEM (2MB, MAP_PRIVATE|MAP_ANONYMOUS|MAP_HUGETLB attempt)
    mov rax, 9              ; sys_mmap
    xor rdi, rdi
    mov rsi, 2 * 1024 * 1024 ; 2MB
    mov rdx, 3              ; PROT_READ | PROT_WRITE
    mov r10, 0x22           ; MAP_PRIVATE | MAP_ANONYMOUS
    mov r8, -1
    xor r9, r9
    syscall
    cmp rax, -1
    je .fallback_inet_close_xsk
    mov [xdp_umem_ptr], rax
    mov [xdp_umem_addr], rax

    ; Step 3: Register UMEM with kernel
    mov rax, 54             ; sys_setsockopt
    mov edi, [xsk_fd]
    mov rsi, 283            ; SOL_XDP
    mov rdx, 4              ; XDP_UMEM_REG
    mov r10, xdp_umem_reg
    mov r8, 40              ; sizeof(struct xdp_umem_reg)
    syscall
    cmp eax, 0
    jl .fallback_inet_close_xsk

    ; Step 4: Set FILL ring size
    mov rax, 54
    mov edi, [xsk_fd]
    mov rsi, 283            ; SOL_XDP
    mov rdx, 5              ; XDP_UMEM_FILL_RING
    mov r10, xdp_ring_size
    mov r8, 4
    syscall
    cmp eax, 0
    jl .fallback_inet_close_xsk

    ; Step 5: Set COMPLETION ring size
    mov rax, 54
    mov edi, [xsk_fd]
    mov rsi, 283
    mov rdx, 6              ; XDP_UMEM_COMPLETION_RING
    mov r10, xdp_ring_size
    mov r8, 4
    syscall
    cmp eax, 0
    jl .fallback_inet_close_xsk

    ; Step 6: Set RX ring size
    mov rax, 54
    mov edi, [xsk_fd]
    mov rsi, 283
    mov rdx, 1              ; XDP_RX_RING
    mov r10, xdp_ring_size
    mov r8, 4
    syscall
    cmp eax, 0
    jl .fallback_inet_close_xsk

    ; Step 7: Set TX ring size
    mov rax, 54
    mov edi, [xsk_fd]
    mov rsi, 283
    mov rdx, 2              ; XDP_TX_RING
    mov r10, xdp_ring_size
    mov r8, 4
    syscall
    cmp eax, 0
    jl .fallback_inet_close_xsk

    ; Step 8: mmap the rings (RX ring at offset XDP_PGOFF_RX_RING)
    ; RX ring: offset = XDP_PGOFF_RX_RING = 0
    mov rax, 9
    xor rdi, rdi
    mov rsi, 16384          ; large enough for ring + descriptors
    mov rdx, 3              ; PROT_READ | PROT_WRITE
    mov r10, 0x8001         ; MAP_SHARED | MAP_POPULATE
    mov r8d, [xsk_fd]
    xor r9, r9              ; offset = 0 (RX)
    syscall
    cmp rax, -1
    je .fallback_inet_close_xsk
    mov [xdp_rx_ring], rax

    ; TX ring: offset = XDP_PGOFF_TX_RING = 0x80000000
    mov rax, 9
    xor rdi, rdi
    mov rsi, 16384
    mov rdx, 3
    mov r10, 0x8001
    mov r8d, [xsk_fd]
    mov r9, 0x80000000
    syscall
    cmp rax, -1
    je .fallback_inet_close_xsk
    mov [xdp_tx_ring], rax

    ; FILL ring: offset = XDP_UMEM_PGOFF_FILL_RING = 0x100000000
    mov rax, 9
    xor rdi, rdi
    mov rsi, 16384
    mov rdx, 3
    mov r10, 0x8001
    mov r8d, [xsk_fd]
    mov r9, 0x100000000
    syscall
    cmp rax, -1
    je .fallback_inet_close_xsk
    mov [xdp_fill_ring], rax

    ; COMPLETION ring: offset = XDP_UMEM_PGOFF_COMPLETION_RING = 0x180000000
    mov rax, 9
    xor rdi, rdi
    mov rsi, 16384
    mov rdx, 3
    mov r10, 0x8001
    mov r8d, [xsk_fd]
    mov r9, 0x180000000
    syscall
    cmp rax, -1
    je .fallback_inet_close_xsk
    mov [xdp_comp_ring], rax

    ; Step 9: Pre-fill FILL ring with UMEM frame offsets
    mov rcx, [xdp_fill_ring]
    ; The ring structure: producer(4B) + pad(4B) + consumer(4B) + pad(4B) + flags(4B) + pad(12B) + desc[]
    ; Descriptors start at offset 64 in the ring
    lea rdi, [rcx + 64]     ; descriptor array
    xor eax, eax
    mov edx, 512             ; fill 512 frames
.fill_umem_frames:
    mov dword [rdi], eax     ; frame offset = idx * 4096
    add rdi, 8               ; next descriptor (u64)
    add eax, 4096
    dec edx
    jnz .fill_umem_frames
    ; Set producer = 512 (we've filled all frames)
    mov dword [rcx], 512
    mov dword [xdp_fill_prod], 512

    ; Step 10: Get interface index for eth0
    ; Use ioctl(SIOCGIFINDEX) on a temporary socket
    sub rsp, 40              ; struct ifreq (40 bytes)
    mov rdi, rsp
    mov rsi, xdp_ifname
    ; Copy "eth0\0" to ifreq.ifr_name
    mov eax, [rsi]
    mov [rdi], eax
    mov byte [rdi+4], 0
    ; ioctl(xsk_fd, SIOCGIFINDEX=0x8933, &ifreq)
    mov rax, 16              ; sys_ioctl
    mov edi, [xsk_fd]
    mov rsi, 0x8933          ; SIOCGIFINDEX
    mov rdx, rsp
    syscall
    cmp eax, 0
    jl .fallback_inet_cleanup
    mov eax, [rsp + 16]      ; ifreq.ifr_ifindex
    mov [xdp_ifindex], eax
    mov [xdp_sa_ifidx], eax
    add rsp, 40

    ; Step 11: Bind AF_XDP socket to interface + queue
    mov rax, 49              ; sys_bind
    mov edi, [xsk_fd]
    mov rsi, xdp_sa
    mov rdx, 16              ; sizeof(struct sockaddr_xdp)
    syscall
    cmp eax, 0
    jl .fallback_inet_close_xsk

    ; Log success
    cmp r14, 1
    jne .skip_xdp_setup_log
    push r12
    mov rax, 1
    mov rdi, 1
    mov rsi, msg_xdp_umem_ok
    mov rdx, msg_xdp_umem_ok_len
    syscall
    pop r12
.skip_xdp_setup_log:

    ; AF_XDP is ready! Enter the XDP fast-path event loop
    jmp xdp_event_loop

.fallback_inet_cleanup:
    add rsp, 40
.fallback_inet_close_xsk:
    ; Close XSK socket and fallback
    mov rax, 3
    mov edi, [xsk_fd]
    syscall

.fallback_inet:
    mov byte [xdp_enabled], 0
    cmp r14, 1
    jne .socket_inet
    push r12
    mov rax, 1
    mov rdi, 1
    mov rsi, msg_xdp_ko
    mov rdx, msg_xdp_ko_len
    syscall
    pop r12

.socket_inet:
    ; --- EXTRACT UNIQUE PORTS ---
    mov dword [listen_count], 0
    
    ; Add default port
    movzx eax, word [sockaddr_port]
    test eax, eax
    jz .check_vhost_ports      ; If 0, wait for vhosts
    mov [bound_ports], ax
    mov dword [listen_count], 1

.check_vhost_ports:
    mov ebx, [vhost_count_global]
    xor ecx, ecx               ; i = 0
.port_vhost_loop:
    cmp ecx, ebx
    jge .bind_ports
    
    mov eax, 2048
    imul eax, ecx
    movzx r8d, word [vhosts + rax + 316] ; port is at offset 316
    test r8d, r8d
    jz .port_v_next
    
    ; Check if port exists in bound_ports
    mov r9d, [listen_count]
    xor r10d, r10d             ; j = 0
.port_dupe_loop:
    cmp r10d, r9d
    jge .port_add              ; not found -> add it
    cmp r8w, [bound_ports + r10*2]
    je .port_v_next            ; fool -> skip
    inc r10d
    jmp .port_dupe_loop
    
.port_add:
    mov [bound_ports + r9*2], r8w
    inc r9d
    mov [listen_count], r9d
    
.port_v_next:
    inc ecx
    jmp .port_vhost_loop
    
.bind_ports:
    xor r15d, r15d             ; i = 0
.bind_loop:
    cmp r15d, [listen_count]
    jge .bind_final_ok
    
    ; Patch sockaddr with the current port
    mov ax, [bound_ports + r15*2]
    mov [sockaddr + 2], ax

    ; Normal Linux socket creation
    mov rax, 41
    mov rdi, 2     ; AF_INET
    mov rsi, 1     ; SOCK_STREAM
    mov rdx, 0
    syscall
    mov r12, rax
    mov [listen_fds + r15*4], r12d

    ; Option SO_REUSEPORT (15)
    cmp byte [reuseport_enabled], 1
    jne .skip_reuseport
    mov rax, 54
    mov rdi, r12
    mov rsi, 1      ; SOL_SOCKET
    mov rdx, 15     ; SO_REUSEPORT
    mov r10, optval
    mov r8, 4
    syscall
.skip_reuseport:

    ; Option SO_REUSEADDR (2)
    mov rax, 54
    mov rdi, r12
    mov rsi, 1      ; SOL_SOCKET
    mov rdx, 2      ; SO_REUSEADDR
    mov r10, optval
    mov r8, 4
    syscall

    ; 2. bind
    mov rax, 49
    mov rdi, r12
    mov rsi, sockaddr
    mov rdx, 16
    syscall
    cmp eax, 0
    jl .fatal_bind_error

    ; Option TCP_DEFER_ACCEPT (9)
    mov rax, 54
    mov rdi, r12
    mov rsi, 6      ; SOL_TCP
    mov rdx, 9      ; TCP_DEFER_ACCEPT
    mov r10, optval
    mov r8, 4
    syscall

    ; TCP_FASTOPEN (23)
    mov rax, 54
    mov rdi, r12
    mov rsi, 6      ; SOL_TCP
    mov rdx, 23     ; TCP_FASTOPEN
    mov r10, tfo_qlen
    mov r8, 4
    syscall

    ; 3. listen
    mov rax, 50
    mov rdi, r12
    mov rsi, 10000
    syscall
    cmp eax, 0
    jl .fatal_bind_error

    inc r15d
    jmp .bind_loop

.fatal_bind_error:
    push r12
    mov rax, 1
    mov rdi, 1
    lea rsi, [msg_bind_err]
    mov rdx, 29
    syscall
    pop r12
    mov rax, 60
    mov rdi, 1
    syscall

.bind_final_ok:

    ; === MULTI-FILE CACHE INIT (simple hardcoded approach) ===
    ; 1. mmap cache pool (512KB)
    mov rax, 9
    xor rdi, rdi
    mov rsi, 512 * 1024
    mov rdx, 3
    mov r10, 0x22
    mov r8, -1
    xor r9, r9
    syscall
    mov [cache_pool], rax
    mov [cache_pool_ptr], rax

    ; 2. Zero cache table (1024 entries x 64 bytes = 65536 bytes)
    mov rdi, cache_table
    mov rcx, 8192      ; 65536 / 8 = 8192
    xor rax, rax
    rep stosq

    ; 3. Scan directory and cache all files
    call scan_and_cache_directory

    ; --- Duplicates "/" entry for index.html ---
    mov ecx, [vhost_count_global]
    xor r15d, r15d      ; i = vhost_id = 0
.cache_index_loop:
    cmp r15d, ecx
    jge .cache_final
    
    ; Setup pointer to current vhost
    mov rax, r15
    imul rax, 2048
    lea r8, [vhosts + rax]
    
    ; Loop over index_files for this vhost
    xor r12, r12        ; j = index file counter
    movzx r13, word [r8 + 896] ; index_count
.vhost_idx_loop:
    cmp r12, r13
    jge .next_vhost_index
    
    ; Build string "vhost_id" + "/" + index_files[j] + " "
    mov qword [buffer], 0
    mov qword [buffer+8], 0
    mov qword [buffer+16], 0
    mov byte [buffer], '/'
    
    ; Add index_files[j] name
    mov rax, r12
    imul rax, 24
    lea r9, [r8 + 904 + rax] ; pointer to index_files[j]
    lea r14, [buffer + 1]
.copy_idx_name:
    mov bl, [r9]
    test bl, bl
    jz .copy_idx_done
    mov [r14], bl
    inc r14
    inc r9
    jmp .copy_idx_name
.copy_idx_done:
    mov byte [r14], ' '
    
    mov rax, r15        ; vhost_id
    crc32 rax, qword [buffer]
    and rax, 0x3FF
    
    lea rdx, [cache_table]
    shl rax, 6          ; 64 bytes per entry
    add rdx, rax
    
    mov r9, [rdx]       ; ptr
    test r9, r9
    jz .idx_next        ; Not found in cache table, try next index file
    
    ; Found the first matching index file! Hide it as "/".
    mov r10, [rdx + 8]  ; len
    mov r11, [rdx + 16] ; etag
    mov rbx, [rdx + 24] ; fd
    mov r14, [rdx + 32] ; file_size
    
    ; Hash "vhost_id" + "/HTTP/1."
    mov qword [buffer], 0
    mov qword [buffer+8], 0
    mov word [buffer], 0x202F       ; "/ "
    mov dword [buffer+2], 0x50545448 ; "HTTP"
    mov dword [buffer+6], 0x312E312F ; "/1.1"
    
    mov rax, r15        ; vhost_id
    crc32 rax, qword [buffer]
    and rax, 0x3FF
    
    lea rdx, [cache_table]
    shl rax, 6
    add rdx, rax
    
    mov [rdx], r9
    mov [rdx + 8], r10
    mov [rdx + 16], r11
    mov [rdx + 24], rbx
    mov [rdx + 32], r14
    
    ; Break out of the index loop since we found the default index!
    jmp .next_vhost_index
    
.idx_next:
    inc r12
    jmp .vhost_idx_loop

.next_vhost_index:
    inc r15d
    jmp .cache_index_loop
.cache_final:

; === Subroutine: cache_one_file ===
; Input: rdi = path (e.g. "./www/index.html")
;        rsi = vhost_id
;        rdx = root length to strip
; Uses: cache_pool_ptr, cache_table, buffer
    jmp after_cache_sub
cache_one_file:
    push rbp
    mov rbp, rsp
    push r12
    push r13
    push r14
    push r15
    push rbx
    push r8

    mov r12, rdi            ; save path
    mov rbx, rsi            ; save vhost_id
    mov r8,  rdx            ; save doc_root len

    ; Open file
    mov rax, 2
    mov rdi, r12
    xor rsi, rsi
    xor rdx, rdx
    syscall
    cmp rax, 0
    jl .cof_done
    mov r13, rax            ; file fd

    ; fstat
    mov rax, 5
    mov rdi, r13
    mov rsi, stat_buf
    syscall
    mov r14, [stat_buf + 48] ; file_size

    ; Find extension for MIME type
    mov [cof_docroot_len], r8  ; SAVE doc_root len ​​before r8 gets clobbered!
    mov rdi, r12
    xor r8, r8          ; Last dot ptr
.cof_find_end:
    mov al, [rdi]
    test al, al
    jz .cof_eof
    cmp al, '.'
    jne .cof_next_char
    mov r8, rdi
.cof_next_char:
    inc rdi
    jmp .cof_find_end
.cof_eof:
    test r8, r8
    jz .cof_default_mime
    
    ; Compare extension with mime_dict
    mov ecx, dword [mime_count_global]
    lea r9, [mime_dict]
.cof_mime_loop:
    test ecx, ecx
    jz .cof_default_mime
    
    push rcx
    push r8
    push r9
.ext_cmp:
    mov al, [r8]
    mov dl, [r9]        ; Use dl instead of bl to preserve rbx (vhost_id)!
    cmp al, dl
    jne .ext_diff
    test al, al
    jz .ext_match      ; Ext matches!
    inc r8
    inc r9
    jmp .ext_cmp
.ext_diff:
    pop r9
    pop r8
    pop rcx
    add r9, 72         ; Move to next struct mime_mapping
    dec ecx
    jmp .cof_mime_loop
    
.ext_match:
    pop r9             ; r9 holds ptr to matching struct
    pop r8
    pop rcx
    add r9, 8          ; r9 points to mime[0]
    jmp .cof_build_dynamic

.cof_default_mime:
    lea r9, [default_mime_str]

.cof_build_dynamic:
    mov rdi, [cache_pool_ptr]
    mov r15, rdi       ; save start of response
    
    ; 1. Base header
    lea rsi, [hdr_base]
    mov rcx, hdr_base_len
    rep movsb
    
    ; 2. MIME type
    mov rsi, r9
.copy_mime:
    mov al, [rsi]
    test al, al
    jz .mime_done
    mov [rdi], al
    inc rdi
    inc rsi
    jmp .copy_mime
.mime_done:
    
    ; 3. Content length string
    lea rsi, [hdr_cl_str]
    mov rcx, hdr_cl_str_len
    rep movsb

    ; 4. itoa(file_size → r14)
    mov rax, r14
    lea r8, [itoa_buf + 20]
    mov byte [r8], 0
    mov rcx, 0xCCCCCCCCCCCCCCCD
.cof_itoa:
    dec r8
    mov r9, rax
    mul rcx
    shr rdx, 3
    lea r10, [rdx + rdx*4]
    add r10, r10
    sub r9, r10
    add r9b, '0'
    mov [r8], r9b
    mov rax, rdx
    test rax, rax
    jnz .cof_itoa
.cof_cpnum:
    mov al, [r8]
    test al, al
    jz .cof_numend
    mov [rdi], al
    inc rdi
    inc r8
    jmp .cof_cpnum
.cof_numend:
    ; Inject \r\nETag: "
    mov dword [rdi], 0x54450A0D   ; "\r\nAND"
    mov dword [rdi+4], 0x203A6761 ; "ag: "
    mov byte [rdi+8], 0x22        ; '"'
    add rdi, 9

    ; Compute CRC32 of file's mtime and size (use r9, NOT rbx which holds vhost_id!)
    xor r9, r9
    crc32 r9, qword [stat_buf + 88]  ; mtime seconds
    crc32 r9, qword [stat_buf + 48]  ; size

    ; Convert r9d to 8 hex tanks
    mov rcx, 8
    mov r9d, r9d
.hex_loop:
    rol r9d, 4
    mov edx, r9d
    and edx, 0x0F
    cmp dl, 9
    jbe .hex_digit
    add dl, 7
.hex_digit:
    add dl, '0'
    mov [rdi], dl
    inc rdi
    dec rcx
    jnz .hex_loop

    ; The 8 hex digits are at [rdi - 8]!
    ; Save them perfectly into r11 for later insertion into the cache table!
    mov r11, [rdi - 8]
    push r11

    ; Close ETag and add \r\n\r\n (End of Headers)
    mov byte [rdi], 0x22          ; '"'
    mov dword [rdi+1], 0x0A0D0A0D ; "\r\n\r\n"
    add rdi, 5

    ; Check if file is > 32768 bytes (r14)
    cmp r14, 32768
    jg .cof_skip_read_content

    ; Read file content into RAM
    push rdi
    mov rax, 0
    mov rsi, rdi
    mov rdx, r14
    mov rdi, r13
    syscall
    pop rdi
    add rdi, rax
    jmp .cof_done_read

.cof_skip_read_content:
    ; Do NOT close the file! We need r13 (FD) for sendfile later!
    ; We skip the read, so rdi (pool ptr) remains just after the headers.

.cof_done_read:
    ; DO NOT CLOSE FILE! The async sendfile engine needs the FD!
    ; push rdi
    ; mov rax, 3
    ; mov rdi, r13
    ; syscall
    ; pop rdi

    ; Update pool pointer
    mov [cache_pool_ptr], rdi

    ; Compute URI: strip doc_root from path -> get "filename" -> prepend "/"
    mov rsi, r12
    add rsi, [cof_docroot_len]  ; FIX: use saved doc_root len, not clobbered r8
    
    mov rdi, buffer
    mov qword [rdi], 0
    mov qword [rdi+8], 0
    mov qword [rdi+16], 0
    
    mov byte [rdi], '/'
    inc rdi
.cof_cp_uri:
    mov al, [rsi]
    mov [rdi], al
    test al, al
    jz .cof_uri_end
    inc rsi
    inc rdi
    jmp .cof_cp_uri
.cof_uri_end:
    ; The null terminator was written at [rdi] by the copy loop.
    ; Overwrite it with space to match raw HTTP request pattern: "/file HTTP/1."
    mov byte [rdi], ' '
    ; Pad URI with exact sequence found in live requests: "HTTP/1."
    mov rax, 0x2E312F5054544820  ; “HTTP/1.” but we already wrote the space
    ; Actually we need "HTTP/1.1" after the space
    mov dword [rdi+1], 0x50545448  ; "HTTP"
    mov dword [rdi+5], 0x312E312F  ; "/1.1"

    ; CRC32 hash (vhost_id + URI)
    mov rax, rbx             ; start hash with vhost_id!
    crc32 rax, qword [buffer]
    and rax, 0x3FF

    ; Store in cache table
    lea rcx, [cache_table]
    shl rax, 6               ; 64 bytes per entry (was 32)
    mov [rcx + rax], r15     ; response ptr (Headers start)
    
    ; Recalculate headers length: total = pool_ptr - start
    mov rdx, [cache_pool_ptr]
    sub rdx, r15
    mov [rcx + rax + 8], rdx ; headers len

    ; Save the securely captured 8-byte hex ETag string (from r11 above)
    pop r11
    mov [rcx + rax + 16], r11 ; Store hex ETag in cache table

    ; Save the raw file descriptor into the 24th byte offset for async sys_sendfile!
    mov [rcx + rax + 24], r13

    ; Save the TOTAL DISK FILE SIZE into the 32nd byte offset
    mov [rcx + rax + 32], r14

    ; Save the first 8 bytes of the URI key for collision detection on lookup
    mov r10, [buffer]
    mov [rcx + rax + 40], r10

.cof_done:
    pop r8
    pop rbx
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    ret
after_cache_sub:

    cmp byte [uring_enabled], 1
    je uring_setup

    ; TCP_NODELAY on listening socket (inherited by accepted sockets)
    mov rax, 54
    mov rdi, r12
    mov rsi, 6      ; SOL_TCP
    mov rdx, 1      ; TCP_NODELAY
    mov r10, optval
    mov r8, 4
    syscall

accept_loop:
    ; 4. accept4 (Fallback in case io_uring is forbidden by Docker Seccomp)
    mov r12d, dword [listen_fds]  ; Restore first socket FD since r12 was overwritten
    mov dword [client_addr_len], 16
    mov rax, 288        ; sys_accept4
    mov rdi, r12
    mov rsi, client_addr
    mov rdx, client_addr_len
    xor r10, r10        ; flags = 0 (blocking socket for synchronous read)
    syscall
    
    ; CORRECTION: If accept fails (eg: too many connections at once with wrk), we ignore and loop
    cmp rax, 0
    jge .accept_ok
    
    ; Break infinite loop if socket is destroyed or invalid
    cmp rax, -11 ; -EAGAIN
    je .accept_retry
    
    ; Any OTHER error means the socket is broken (or syscall failed). Print error!
    push r12
    mov rax, 1
    mov rdi, 1
    lea rsi, [msg_accept_err]
    mov rdx, 35
    syscall
    pop r12
    mov rax, 60
    xor rdi, rdi
    syscall
    
.accept_retry:
    ; On shutdown, exit gracefully
    cmp byte [shutdown_flag], 1
    je .graceful_exit
    jmp accept_loop
.graceful_exit:
    mov rax, 60
    xor rdi, rdi
    syscall
.accept_ok:
    
    mov r13, rax

    ; Set SO_RCVTIMEO (5s keep-alive timeout)
    mov rax, 54             ; setsockopt
    mov rdi, r13
    mov rsi, 1              ; SOL_SOCKET
    mov rdx, 20             ; SO_RCVTIMEO
    mov r10, ka_timeout
    mov r8, 16              ; sizeof(struct timeval)
    syscall

    ; 5. read
read_request:
    ; Check graceful shutdown flag
    cmp byte [shutdown_flag], 1
    je close_conn
    ; Check SIGHUP reload flag
    cmp byte [reload_flag], 1
    jne .no_reload
    mov byte [reload_flag], 0
    call reload_cache
.no_reload:
    mov rax, 0
    mov rdi, r13
    mov rsi, buffer
    mov rdx, 4096
    syscall
    
    test rax, rax
    jle close_conn

    ; --- PIPELINE BUFFER LIMITS ---
    mov r9, rax     ; rax = exact bytes read by sys_read
    add r9, buffer
    mov r8d, dword [cur_slot]
    mov [slot_pipeline_end_buf + r8*8], r9
    mov rsi, buffer

read_request_parse_buffer_loop:
    mov r8d, dword [cur_slot]
    mov [slot_proxy_req_ptr + r8*8], rsi   ; SAVE TRUE START POINTER OF THIS REQUEST
    mov dword [slot_vhost_id + r8*4], 0
    mov qword [slot_range_offset + r8*8], 0
    mov qword [slot_range_end + r8*8], -1
    mov r9, [slot_pipeline_end_buf + r8*8]
    cmp rsi, r9
    jl .pipeline_ok
    ; All pipeline requests extracted
    cmp byte [uring_enabled], 1
    je uring_keepalive_loop
    jmp read_request           ; Legacy: blocking read for next keep-alive request
.pipeline_ok:

    mov rax, r9
    sub rax, rsi
    cmp rax, 4
    jge .pipeline_has_data
    ; Fragmented: not enough bytes
    cmp byte [uring_enabled], 1
    je uring_keepalive_loop
    jmp read_request           ; Legacy: blocking read for more data
.pipeline_has_data:

    mov r8d, dword [cur_slot]
    mov byte [slot_method + r8], 0  ; default to GET(0)
    
    cmp dword [rsi], 0x20544547   ; “GET”
    je .method_found_4
    
    ; Check HEAD (“HEAD”)
    cmp dword [rsi], 0x44414548   ; “HEAD”
    jne .check_post
    cmp byte [rsi + 4], ' '
    jne close_conn
    mov byte [slot_method + r8], 1  ; 1 = HEAD
    add rsi, 5
    jmp .method_done
    
.check_post:
    cmp dword [rsi], 0x54534F50   ; "POST"
    jne .check_put
    cmp byte [rsi + 4], ' '
    jne close_conn
    mov byte [slot_method + r8], 2  ; 2 = POST
    add rsi, 5
    jmp .method_done

.check_put:
    cmp dword [rsi], 0x20545550   ; “PUT”
    jne .check_delete
    mov byte [slot_method + r8], 3  ; 3 = PUT
    add rsi, 4
    jmp .method_done

.check_delete:
    cmp dword [rsi], 0x454C4544   ; “DELE”
    jne .check_options
    cmp word [rsi + 4], 0x4554    ; "YOU"
    jne close_conn
    cmp byte [rsi + 6], ' '       ; " "
    jne close_conn
    mov byte [slot_method + r8], 4  ; 4 = DELETE
    add rsi, 7
    jmp .method_done

.check_options:
    cmp dword [rsi], 0x4954504F   ; “OPTI”
    jne .check_patch
    cmp dword [rsi + 4], 0x20534E4F ; “ONS”
    jne close_conn
    mov byte [slot_method + r8], 5  ; 5 = OPTIONS
    add rsi, 8
    jmp .method_done

.check_patch:
    cmp dword [rsi], 0x43544150   ; “PATC”
    jne .check_other
    cmp word [rsi + 4], 0x2048    ; “H”
    jne close_conn
    mov byte [slot_method + r8], 6  ; 6 = PATCH
    add rsi, 6
    jmp .method_done

.check_other:
    ; Unknown method, skip to space
    mov byte [slot_method + r8], 10 ; 10 = OTHER
.skip_method_loop:
    cmp byte [rsi], ' '
    je .found_space
    inc rsi
    cmp rsi, r9
    jge close_conn
    jmp .skip_method_loop
.found_space:
    inc rsi
    jmp .method_done

.method_found_4:
    add rsi, 4
.method_done:

    ; --- LFI Prevention (Path Traversal + URL Encoding Bypass) ---
    mov r10, rsi
.lfi_scan:
    cmp r10, r9
    jge .lfi_clean
    mov al, [r10]
    cmp al, ' '
    je .lfi_clean
    cmp al, '?'
    je .lfi_clean
    ; Block URL-encoded traversal: reject any '%' (prevents %2e%2e, %00, etc.)
    cmp al, '%'
    je send_404
    ; Block null bytes (path truncation attack)
    test al, al
    jz send_404
    ; Block raw "../" traversal
    cmp word [r10], 0x2E2E  ; ".."
    jne .lfi_next
    cmp byte [r10+2], '/'   ; "../"
    je send_404
.lfi_next:
    inc r10
    jmp .lfi_scan
.lfi_clean:

    ; === ACCESS LOGGING (stdout) ===
    cmp byte [access_log_enabled], 1
    jne .skip_logging
    
    push rax
    push rdi
    push rsi
    push rdx
    push rcx
    push r11
    
    mov r9, rsi             ; r9 = original URI pointer
    mov r10, log_format_string
    mov rdi, log_buf

.format_loop:
    mov al, [r10]
    cmp al, 0
    je .format_done
    
    cmp al, '%'
    jne .copy_literal
    
    inc r10
    mov al, [r10]
    cmp al, 'm'
    je .copy_method
    cmp al, 'u'
    je .copy_uri
    cmp al, 'h'
    je .copy_ip
    cmp al, 't'
    je .copy_time
    cmp al, 'p'
    je .copy_proto
    
    ; Copy just '%' and char if unknown
    mov byte [rdi], '%'
    inc rdi
    mov [rdi], al
    inc rdi
    inc r10
    jmp .format_loop

.copy_literal:
    mov [rdi], al
    inc rdi
    inc r10
    jmp .format_loop

.copy_method:
    mov r8, r9
    sub r8, 4               ; Point back to HTTP Method ("GET")
.copy_m_loop:
    mov al, [r8]
    cmp al, ' '
    je .copy_m_done
    mov [rdi], al
    inc rdi
    inc r8
    jmp .copy_m_loop
.copy_m_done:
    inc r10
    jmp .format_loop

.copy_uri:
    mov r8, r9
.copy_u_loop:
    mov al, [r8]
    cmp al, ' '
    je .copy_u_done
    cmp al, '?'
    je .copy_u_done
    mov [rdi], al
    inc rdi
    inc r8
    ; bounds check
    lea rax, [log_buf + 250]
    cmp rdi, rax
    jge .copy_u_done
    jmp .copy_u_loop
.copy_u_done:
    inc r10
    jmp .format_loop

.copy_proto:
    mov dword [rdi], 0x50545448 ; "HTTP"
    add rdi, 4
    mov dword [rdi], 0x312E312F ; "/1.1"
    add rdi, 4
    inc r10
    jmp .format_loop

.copy_time:
    ; Get timestamp sys_time
    push rax
    push rdi
    mov rax, 201
    mov rdi, unix_time
    syscall
    pop rdi
    pop rax
    
    ; Convert [unix_time] to string
    mov rax, [unix_time]
    push r8
    push rcx
    push rdx
    mov rcx, 0xCCCCCCCCCCCCCCCD
    mov r8, log_buf + 250    ; Temporary end pointer for digits
.time_div:
    mov r9, rax
    mul rcx
    shr rdx, 3
    lea r10, [rdx + rdx*4]
    add r10, r10
    sub r9, r10
    add r9b, '0'
    dec r8
    mov [r8], r9b
    mov rax, rdx
    test rax, rax
    jnz .time_div
    ; Copy from r8 to rdi
.time_copy:
    mov al, [r8]
    mov [rdi], al
    inc rdi
    inc r8
    cmp r8, log_buf + 250
    jl .time_copy
    pop rdx
    pop rcx
    pop r8
    inc r10
    jmp .format_loop

.copy_ip:
    ; client_addr is a sockaddr_in
    ; offset 4 contains 4 bytes of IPv4, e.g. 127.0.0.1 (uint32_t)
    push rax
    push r8
    push rcx
    push rdx
    mov r8d, dword [client_addr + 4]
    ; Byte 0
    movzx eax, r8b
    call _itoa_8
    mov byte [rdi], '.' 
    inc rdi
    ; Byte 1
    shr r8, 8
    movzx eax, r8b
    call _itoa_8
    mov byte [rdi], '.' 
    inc rdi
    ; Bytes 2
    shr r8, 8
    movzx eax, r8b
    call _itoa_8
    mov byte [rdi], '.' 
    inc rdi
    ; Bytes 3
    shr r8, 8
    movzx eax, r8b
    call _itoa_8
    pop rdx
    pop rcx
    pop r8
    pop rax
    inc r10
    jmp .format_loop

.format_done:
    ; Add newline
    mov byte [rdi], 13
    mov byte [rdi+1], 10
    add rdi, 2
    
    ; Calculate slot buffer address and length
    mov rsi, log_buf
    mov rdx, rdi
    sub rdx, rsi     ; rdx = length
    
    push r14          ; SAVE r14
    mov eax, [cur_slot]
    shl eax, 8        ; slot * 256
    lea r14, [slot_log_buf]
    add r14, rax      ; r14 = destination

    ; Fast memory copy from log_buf to slot_log_buf
    push rcx
    push rdi
    mov rcx, rdx
    mov rdi, r14      ; dest
    ; rsi already source (log_buf)
    rep movsb
    pop rdi
    pop rcx

    ; submit via io_uring asynchronously
    ; r14 is now the address
    push r15
    mov r15, r14
    call submit_access_log_async
    pop r15
    pop r14


    
    pop r11
    pop rcx
    pop rdx
    pop rsi
    pop rdi
    pop rax
    ; === END ACCESS LOGGING ===
.skip_logging:

    ; --- PIPELINE EXTRACTOR ---
    mov [legacy_client_fd], r13  ; Save client_fd before headers clobber r13!
    mov r12, rsi                  ; Copy URI pointer so we can scan forward
    push rax
    mov eax, dword [cur_slot]
    mov r9, [slot_pipeline_end_buf + rax*8]
    pop rax
.scan_headers:
    cmp r12, r9
    jge .headers_end
    
    ; FAST Host Header Parser
    lea rax, [r12 + 8]
    cmp rax, r9
    jge .skip_host_scan
    
    mov rax, 0x203A74736F480A0D ; "\r\nHost: "
    cmp [r12], rax
    je .host_found
    inc r12
    jmp .scan_headers

.host_found:
    ; Found "\r\nHost: ", extract it
    mov rax, r12
    add rax, 8
    
    ; find end of host string (either \r or space)
    mov r10, rax
.find_host_end:
    cmp r10, r9
    jge .host_end_found
    cmp byte [r10], 13 ; CR
    je .host_end_found
    cmp byte [r10], ' '
    je .host_end_found
    cmp byte [r10], ':' ; Port separator (e.g. site1.local:8081)
    je .host_end_found
    inc r10
    jmp .find_host_end
.host_end_found:
    ; Length = r10 - rax
    mov r11, r10
    sub r11, rax
    
    ; Compare with vhosts array
    mov ecx, [vhost_count_global]
    test ecx, ecx
    jz .skip_host_scan
    
    ; --- STRICT PORT-AWARE ROUTING: Fetch the receiving physical port ---
    mov edx, [cur_slot]
    
    ; NEW O(1) ROUTING MAP: slot_listen_fds directly stores the precise
    ; network-byte order port from our handle_accept user_data hack!
    mov edi, [slot_listen_fds + rdx*4]  ; edi = physical receiving port
    test edi, edi
    jnz .port_nonzero
    movzx edi, word [bound_ports]       ; Default to first bound port if TLS manager wiped it
.port_nonzero:
    ; SAFEGUARD DELETED: DO NOT CORRUPT rax (It holds the HTTP Host pointer!)
    ; --- PORT FALLBACK: Pre-assign the first vhost that listens on this port ---
    push r14
    push r15
    lea r14, [vhosts]
    xor r15, r15
.fallback_loop:
    cmp r15d, ecx         ; ecx = vhost_count_global
    jge .fallback_done
    movzx ebx, word [r14 + 316]
    test ebx, ebx
    jnz .fb_check
    movzx ebx, word [sockaddr_port]
.fb_check:
    cmp ebx, edi          ; match physical port?
    jne .fb_next
    mov r8d, [cur_slot]
    mov [slot_vhost_id + r8*4], r15d
    jmp .fallback_done    ; Found default vhost for this port!
.fb_next:
    add r14, 2048
    inc r15d
    jmp .fallback_loop
.fallback_done:
    pop r15
    pop r14
    ; ------------------------------------------------------------------

    lea r14, [vhosts]
    xor r15, r15        ; i = 0
.vhost_match_loop:
    cmp r15d, ecx
    jge .skip_host_scan
    
    ; --- STRICT PORT-AWARE ROUTING: Skip if VHost port mismatches ---
    movzx ebx, word [r14 + 316] ; vhost[i].port
    test ebx, ebx
    jnz .check_port
    movzx ebx, word [sockaddr_port] ; fallback default port
.check_port:
    cmp ebx, edi
    jne .vhost_match_next
    ; ------------------------------------------------------------------

    ; Compare domain string
    push r11
    push rax
    push r14
.domain_cmp:
    test r11, r11
    jz .domain_check_end
    mov dl, [rax]
    cmp dl, [r14]
    jne .domain_diff
    inc rax
    inc r14
    dec r11
    jmp .domain_cmp
.domain_check_end:
    ; Host header fully consumed - domain must also end here
    cmp byte [r14], 0
    jne .domain_diff    ; domain has more chars → not a match
    jmp .domain_match
.domain_diff:
    pop r14
    pop rax
    pop r11
.vhost_match_next:
    add r14, 2048       ; next vhost block
    inc r15d
    jmp .vhost_match_loop

.domain_match:
    pop r14
    pop rax
    pop r11
    ; Match!
    mov r8d, [cur_slot]
    mov [slot_vhost_id + r8*4], r15d

.skip_host_scan:
    mov r13, [legacy_client_fd]

    ; FAST Range Parser
    ; "\nRange: bytes=" check (14 bytes)
    lea rax, [r12 + 14]
    cmp rax, r9
    jge .skip_range_scan
    
    cmp dword [r12], 0x6E61520A ; "\nRan"
    jne .skip_range_scan
    cmp dword [r12+4], 0x203A6567 ; "ge: "
    jne .skip_range_scan
    cmp dword [r12+8], 0x65747962 ; "bytes"
    jne .skip_range_scan
    cmp word [r12+12], 0x3D73 ; "s="
    jne .skip_range_scan
    
    ; Found "\nRange: bytes=" -> Extract AtoI 64-bit
    mov r8, r12
    add r8, 14
    xor rcx, rcx  ; rcx accumulator
.parse_atoi:
    movzx r10, byte [r8]
    cmp r10, '0'
    jl .parse_end
    cmp r10, '9'
    jg .parse_end
    sub r10, '0'
    imul rcx, 10
    add rcx, r10
    inc r8
    jmp .parse_atoi
.parse_end:
    mov r10d, dword [cur_slot]
    mov [slot_range_offset + r10*8], rcx
    cmp byte [r8], '-'
    jne .skip_range_scan
    inc r8
    movzx r11, byte [r8]
    cmp r11, '0'
    jl .skip_range_scan
    cmp r11, '9'
    jg .skip_range_scan
    xor rcx, rcx  ; rcx accumulator for end
.parse_atoi_end:
    movzx r11, byte [r8]
    cmp r11, '0'
    jl .parse_end_end
    cmp r11, '9'
    jg .parse_end_end
    sub r11, '0'
    imul rcx, 10
    add rcx, r11
    inc r8
    jmp .parse_atoi_end
.parse_end_end:
    mov [slot_range_end + r10*8], rcx
.skip_range_scan:

    cmp dword [r12], 0x0A0D0A0D   ; "\r\n\r\n"
    je .found_next
    inc r12
    jmp .scan_headers
.found_next:
    add r12, 4                    ; Skip CRLF CRLF
.headers_end:
    push rax
    mov eax, dword [cur_slot]
    mov [slot_pipeline_next_req + rax*8], r12
    pop rax

    ; --- ZERO OVERHEAD JUMP TABLE ---
    cmp byte [routing_enabled], 1
    jne normal_routing

    mov rax, [rsi]
    mov rbx, [rsi+8]
    xor rcx, rcx
    crc32 rcx, rax
    crc32 rcx, rbx
    and rcx, 0xFF
    lea rdx, [route_jump_table]
    jmp [rdx + rcx*8]
    ; --- END JUMP TABLE ---
normal_routing:
    ; === DYNAMIC PROXIES (NGINX LOCATIONS) ===
    ; 1. Get current vhost struct address
    mov r8d, dword [cur_slot]
    mov eax, [slot_vhost_id + r8*4]
    imul rax, 2048
    lea r12, [vhosts + rax]

    ; 2. Read loc_count from current vhost
    movzx edi, word [r12 + 318]   ; loc_count is at offset 318
    test edi, edi
    jz .not_proxy

    xor r15d, r15d                 ; i = 0 (locations loop index)
.proxy_match_loop:
    cmp r15d, edi
    jge .not_proxy

    ; r11 = &vhost.locs[i]
    ; locs start at 320. Each loc is 144 bytes.
    mov eax, 144
    mul r15d
    lea r11, [r12 + 320 + rax]

    ; determine path_len of locs[i].path (max 31 bytes)
    lea r10, [r11]                ; path is at offset 0
    xor rcx, rcx
.strlen_loc:
    cmp byte [r10 + rcx], 0
    je .strlen_loc_done
    inc rcx
    cmp rcx, 31
    jl .strlen_loc
.strlen_loc_done:
    
    ; compare URI (rsi) with location path (r10), length rcx
    mov r8, rcx
    mov r9, rsi
    
    ; --- AVX2 ROUTING BYPASS ---
    cmp byte [avx512_enabled], 1
    je .avx2_proxy_match
    cmp byte [avx2_enabled], 1
    je .avx2_proxy_match

    ; Fallback byte-by-byte memcmp
.memcmp_loop:
    test rcx, rcx
    jz .proxy_matched
    mov al, [r9]
    mov bl, [r10]
    cmp al, bl
    jne .next_proxy
    inc r9
    inc r10
    dec rcx
    jmp .memcmp_loop

.avx2_proxy_match:
    ; SIMD OOB guard: ensure 32 bytes available from URI before SIMD load
    push rcx
    mov ecx, dword [cur_slot]
    mov rax, [slot_pipeline_end_buf + rcx*8]
    pop rcx
    sub rax, r9
    cmp rax, 32
    jl .memcmp_loop              ; Fallback to scalar if < 32 bytes available

    vmovdqu ymm0, yword [r9]     ; Load 32 bytes of request URI
    vmovdqu ymm1, yword [r10]    ; Load 32-byte structured location path
    vpcmpeqb ymm2, ymm0, ymm1    ; Parallel byte equality comparison
    vpmovmskb eax, ymm2          ; Extract 32-bit match mask

    ; Generate dynamic route_len (cl) fast-mask
    mov edx, 1
    mov cl, r8b                  ; rcx was trashed, but r8 has length
    shl edx, cl
    dec edx

    and eax, edx
    cmp eax, edx
    je .proxy_matched            ; Exact topological match!
    jmp .next_proxy

.proxy_matched:
    ; It's a match!
    ; Is it an actual proxy_pass?
    movzx eax, word [r11 + 140]  ; is_proxy feature flag
    test eax, eax
    jz .next_proxy               ; if not a proxy, continue (maybe static locs later)

    mov r8d, [cur_slot]
    ; Initialize state to 1 (active) so that CQEs are mapped properly
    mov byte [slot_proxy_state + r8], 1

    ; [NEW] Remember unique route ID = (vhost * 16) + loc
    mov eax, [slot_vhost_id + r8*4]
    shl eax, 4
    add eax, r15d
    mov [slot_proxy_loc_idx + r8*4], eax

    ; We need the proxy sockaddr to persist across Async IO. We construct it in slot_proxy_sockaddr.
    mov eax, 110
    mul r8d
    lea r10, [slot_proxy_sockaddr + rax] ; r10 = sockaddr address for this connection

    ; Copy the full native sockaddr blob (up to 110 bytes alloc, copying 112 bytes safely)
    ; It natively contains family and address structures
    push rsi
    push rdi
    push rcx

    lea rsi, [r11 + 32]          ; Source: loc.proxy_sockaddr starts at offset 32
    mov rdi, r10                 ; Target: slot_proxy_sockaddr + offset
    mov rcx, 14                  ; 14 * 8 = 112 bytes
    rep movsq

    pop rcx
    pop rdi
    pop rsi

    jmp .handle_proxy_request_dynamic

.next_proxy:
    inc r15d
    jmp .proxy_match_loop

.handle_proxy_request_dynamic:
    mov r9d, [cur_slot]

    ; --- 1. PREPARE ASYNC PROXY BUFFER ---
    mov rsi, [slot_proxy_req_ptr + r9*8] ; Retrieve true start of this request
    mov r12, [slot_pipeline_next_req + r9*8]
    mov rcx, r12
    sub rcx, rsi                ; Default to header length

    ; Check if request has body (Method POST=2, PUT=3, PATCH=6)
    cmp byte [slot_method + r9], 2
    je .req_parse_cl
    cmp byte [slot_method + r9], 3
    je .req_parse_cl
    cmp byte [slot_method + r9], 6
    je .req_parse_cl
    jmp .req_cl_done

.req_parse_cl:
    push rsi
    mov r10, r12                ; r10 = End of headers
    
    cmp byte [avx2_enabled], 1
    je .req_cl_simd_dispatch
    cmp byte [avx512_enabled], 1
    je .req_cl_simd_dispatch
    jmp .req_cl_loop_scalar

.req_cl_simd_dispatch:
    ; --- AVX2 SIMD SETUP for Request Header Scan ---
    vpbroadcastb ymm1, [rel .c_lower]
    vpbroadcastb ymm2, [rel .c_upper]
    vpbroadcastb ymm3, [rel .t_lower]
    vpbroadcastb ymm4, [rel .t_upper]

.req_cl_loop_avx:
    mov rax, r10
    sub rax, rsi
    cmp rax, 32
    jb .req_cl_loop_scalar      ; Fallback to scalar for tail

    vmovdqu ymm0, [rsi]
    vpcmpeqb ymm5, ymm0, ymm1   ; Match 'c'
    vpcmpeqb ymm6, ymm0, ymm2   ; Match 'C'
    vpor ymm5, ymm5, ymm6
    vpcmpeqb ymm6, ymm0, ymm3   ; Match 't'
    vpor ymm5, ymm5, ymm6
    vpcmpeqb ymm6, ymm0, ymm4   ; Match 'T'
    vpor ymm5, ymm5, ymm6

    vpmovmskb eax, ymm5
    test eax, eax
    jnz .req_cl_simd_match
    
    add rsi, 32
    jmp .req_cl_loop_avx

.req_cl_simd_match:
    tzcnt ebx, eax
    add rsi, rbx
    
    ; BOUNDARY CHECK: Must be preceded by \n to prevent X-Content-Length bypass (HTTP Smuggling)
    cmp rsi, r12
    jle .req_cl_check             ; If it's the exact start of headers, it's safe
    cmp byte [rsi-1], 0x0A
    je .req_cl_check
    
    ; False positive (like X-Content-Length), continue searching
    inc rsi
    jmp .req_cl_loop_avx

.req_cl_loop_scalar:
    cmp rsi, r10
    jge .req_cl_fail
    mov al, [rsi]
    or al, 0x20                 ; Lowercase
    cmp al, 'c'
    je .req_cl_check
    cmp al, 't'
    je .req_cl_check
    inc rsi
    jmp .req_cl_loop_scalar

.req_cl_check:
    ; --- SECURITY: Boundary Verification ---
    cmp rsi, r12
    jle .req_cl_check_ok
    cmp byte [rsi-1], 0x0A
    jne .req_cl_next
.req_cl_check_ok:
    ; Check if it's Content-Length
    mov rax, [rsi]
    mov r11, 0x2020202020202020
    or rax, r11                 ; Case-insensitive check
    mov r14, 0x2D746E65746E6F63 ; 'content-' (reversed)
    cmp rax, r14
    jne .req_te_check
    
    ; 'Length' check
    mov eax, [rsi+8]
    or eax, 0x20202020
    cmp eax, 0x6874676E         ; 'long'
    jne .req_cl_next
    cmp byte [rsi+13], ':'
    je .req_cl_matched
    cmp byte [rsi+14], ':'
    jne .req_cl_next

.req_cl_matched:
    ; Point to value start
    add rsi, 14
    jmp .skip_cl_spaces

.req_te_check:
    ; Check for Transfer-Encoding
    ; 'transfer'
    mov r14, 0x726566736E617274 ; 'transfer'
    cmp rax, r14
    jne .req_cl_next
    ; '-encodin'
    mov rax, [rsi+8]
    mov r11, 0x2020202020202020
    or rax, r11
    mov r14, 0x6769646F636E652D ; '-encodin'
    cmp rax, r14
    jne .req_cl_next
    
    ; Found TE! We don't support it for plain dynamic proxy, fail for safety or infinity.
    ; NEVER forward HTTP/1.1 chunked bodies to proxy if not parsing them, it causes Pipelined Request Smuggling!
    ; DROP THE CONNECTION!
    pop rsi                        ; Restore stack
    jmp close_conn                 ; Disconnect client maliciously smuggling TE

.req_cl_next:
    inc rsi
    jmp .req_cl_loop_avx

.c_lower: db 'c'
.c_upper: db 'C'
.t_lower: db 't'
.t_upper: db 'T'

.req_cl_match:
    add rsi, 10
.skip_cl_spaces:
    cmp byte [rsi], ' '
    je .skip_cl_space_inc
    cmp byte [rsi], ':'
    je .skip_cl_space_inc
    cmp byte [rsi], 'g'
    je .skip_cl_space_inc
    cmp byte [rsi], 't'
    je .skip_cl_space_inc
    cmp byte [rsi], 'h'
    je .skip_cl_space_inc
    jmp .req_cl_atoi_start
.skip_cl_space_inc:
    inc rsi
    jmp .skip_cl_spaces

.req_cl_atoi_start:
    xor ebx, ebx
.req_cl_atoi:
    movzx eax, byte [rsi]
    cmp eax, '0'
    jb .req_cl_found
    cmp eax, '9'
    ja .req_cl_found
    sub eax, '0'
    imul ebx, 10
    add ebx, eax
    inc rsi
    jmp .req_cl_atoi

.req_cl_found:
    add rcx, rbx ; add body length to rcx!
    ; UPDATE pipeline_next_req to include body!
    add r12, rbx
    mov [slot_pipeline_next_req + r9*8], r12
    jmp .req_cl_fail

    jmp .req_cl_fail

.req_cl_fail_with_rc:
    mov [slot_proxy_req_len + r9*4], ecx ; rcx was set to infinity or calculated len
.req_cl_fail:
    pop rsi
.req_cl_done:
    ; Check if bounded correctly
    push r8
    push rax
    mov eax, dword [cur_slot]
    mov r8, [slot_pipeline_end_buf + rax*8]
    pop rax
    sub r8, rsi
    cmp rcx, r8
    jle .req_cl_ok
    mov rcx, r8
.req_cl_ok:
    pop r8
    mov [slot_proxy_req_len + r9*4], ecx
    mov [slot_proxy_req_ptr + r9*8], rsi

    ; check if proxy connection already exists (reuse from previous request)
    mov r9d, [cur_slot]
    mov r14d, [slot_proxy_fds + r9*4]
    cmp r14d, 0
    jg .proxy_connected_fastpath

    ; === CONNECTION POOL: Try to acquire a pre-connected fd ===
    push r9
    call proxy_pool_acquire             ; returns edi = fd or -1
    pop r9
    cmp edi, 0
    jl .proxy_pool_miss                 ; pool empty → old path

    ; Pool hit! Use the pre-connected fd directly.
    mov r14d, edi
    jmp .proxy_pool_hit

.proxy_pool_miss:
    ; Fallback: create new connection (socket + connect)
    mov r8d, dword [cur_slot]
    mov eax, 110
    mul r8d
    lea r10, [slot_proxy_sockaddr + rax]

    ; Is it an upstream?
    cmp word [r10], 0xFF
    jne .dyn_upstream_done

    ; --- DYNAMIC LOAD BALANCING RESOLUTION ---
    ; Get the upstream_id from [r10 + 2]
    movzx esi, byte [r10 + 2]   ; esi = upstream index
    imul rsi, 1904              ; Size of upstream_group is 1904 bytes
    lea r15, [upstreams_list + rsi] ; r15 = &upstreams_list[index]

    mov ecx, [r15 + 32]         ; ecx = server_count
    cmp ecx, 0
    jle .proxy_err_st1          ; Empty upstream!
    
    ; Determine Algorithm
    mov edx, [r15 + 36]         ; edx = algorithm (0: RR, 1: Hash, 2: Least)
    cmp edx, 1
    je .lb_ip_hash
    cmp edx, 2
    je .lb_least_conn

.lb_round_robin:
    ; RR: current_rr % server_count
    mov rax, [r15 + 1768]       ; current_rr
    lock add qword [r15 + 1768], 1
    xor edx, edx
    div rcx                     ; rdx = remainder (server index)
    jmp .lb_apply_server

.lb_ip_hash:
    ; Session Hash (IP_Hash equivalent): CRC32(cur_slot) % server_count
    ; Ensures TCP Keep-Alive connections stay pinned deterministically
    mov eax, r8d                ; r8d = cur_slot
    xor edx, edx
    crc32 edx, eax
    mov eax, edx
    xor edx, edx
    div rcx                     ; rdx = remainder (server index)
    jmp .lb_apply_server

.lb_least_conn:
    ; Least Conn: find min active_connections
    xor ebx, ebx                ; ebx = i
    xor edx, edx                ; edx = best index (default 0)
    mov r11, 0x7FFFFFFFFFFFFFFF ; max pos long
.lb_lc_loop:
    cmp ebx, ecx
    jge .lb_apply_server
    mov rax, [r15 + 1776 + rbx*8]
    cmp rax, r11
    jge .lb_lc_next
    mov r11, rax
    mov edx, ebx                ; best index = i
.lb_lc_next:
    inc ebx
    jmp .lb_lc_loop

.lb_apply_server:
    ; Record connection for least_conn decrement on close
    lock add qword [r15 + 1776 + rdx*8], 1
    
    ; Combine upstream_id and server_id (edx) into a single 16-bit word
    ; High byte: upstream_id (esi), Low byte: server_id (edx)
    shl esi, 8
    or esi, edx
    mov [slot_proxy_lb_meta + r8*2], si

    ; Overwrite slot_proxy_sockaddr with the ACTUAL selected server details
    ; Family is at [r15 + 40 + rdx*2]
    ; Addrs is at [r15 + 72 + rdx*106]
    movzx ebx, word [r15 + 40 + rdx*2]    ; CopyFamily
    mov word [r10], bx

    ; Calculate addr offset
    mov eax, 106
    imul rax, rdx
    lea rSI, [r15 + 72 + rax]              ; Source: addrs[edx]
    
    push rdi
    push r10
    push rcx
    lea rdi, [r10 + 2]                    ; Dest: slot_proxy_sockaddr payload
    mov rcx, 14                           ; Copy roughly 106 bytes -> 14 qwords
    rep movsq
    pop rcx
    pop r10
    pop rdi

.dyn_upstream_done:
    ; --- SOCK_STREAM CREATION ---
    mov rax, 41
    movzx rdi, word [r10]      ; Dynamic Domain Family (AF_UNIX=1, AF_INET=2)
    mov rsi, 1                 ; SOCK_STREAM
    mov rdx, 0
    syscall
    cmp rax, 0
    jl .proxy_err_st1

    mov r14, rax    ; new proxy fd
    mov r9d, [cur_slot]
.pool_miss_skip_pipe:
    ; Save proxy FD and compute request length
    mov [slot_proxy_fds + r9*4], r14d
    mov eax, r9d
    shl eax, 12
    add rax, [conn_pool]
    push rax
    mov eax, dword [cur_slot]
    mov r8, [slot_pipeline_end_buf + rax*8]
    pop rax
    sub r8, rax
    mov [slot_proxy_req_len + r9*4], r8d

    ; Synchronous connect
    mov r8d, r9d
    mov eax, 110
    mul r8d
    lea r10, [slot_proxy_sockaddr + rax]

    movzx rbx, word [r10]
    cmp rbx, 2
    je .pool_miss_inet_len

.pool_miss_unix_len:
    lea rdi, [r10 + 2]
    xor ecx, ecx
.pool_miss_strlen:
    mov al, [rdi + rcx]
    cmp al, 0
    je .pool_miss_strlen_done
    inc ecx
    jmp .pool_miss_strlen
.pool_miss_strlen_done:
    add ecx, 3
    jmp .do_connect

.pool_miss_inet_len:
    mov rcx, 16      ; sizeof(sockaddr_in)

.do_connect:
    mov rax, 42
    mov rdi, r14
    mov rsi, r10
    mov rdx, rcx
    syscall

    cmp rax, 0
    jl .proxy_err_st1

    ; Connection succeeded — go to write
    jmp .proxy_do_write

.proxy_pool_hit:
    ; Pool-acquired fd — save it and compute request length
    mov r9d, [cur_slot]
    mov [slot_proxy_fds + r9*4], r14d

    ; Compute request length (same as pool_miss path)
    mov eax, r9d
    shl eax, 12
    add rax, [conn_pool]
    push rax
    mov eax, dword [cur_slot]
    mov r8, [slot_pipeline_end_buf + rax*8]
    pop rax
    sub r8, rax
    mov [slot_proxy_req_len + r9*4], r8d

.proxy_connected_fastpath:
    jmp .proxy_do_write

.proxy_do_write:
    ; ==========================================
    ; HYBRID / ASYNC PROXY DISPATCHER
    ; ==========================================
    mov r8d, [cur_slot]

    cmp byte [slot_proxy_state + r8], 1
    je .proxy_do_write_splice
    
    ; --- FULLY ASYNC KERNEL QUEUE ---
    mov rsi, [slot_proxy_req_ptr + r8*8]
    mov edx, [slot_proxy_req_len + r8*4]
    
    call uring_submit_proxy_send_sqe
    mov r8d, [cqe_saved_head]
    mov r15d, [cqe_saved_tail]
    jmp uring_cqe_continue

.proxy_do_write_splice:
    ; --- FASTPATH: 100% ASYNC ZC SPLICE ---
    mov byte [slot_proxy_state + r8], 1    ; Declare proxy active to not drop CQEs
    
    ; Phase 1: Allocate dynamically sized pipe2 for Zero-Copy if missing
    cmp dword [slot_proxy_pipe_w + r8*4], 0
    jne .proxy_pipe_ready
    
    sub rsp, 16
    mov rax, 293           ; sys_pipe2
    mov rdi, rsp
    mov rsi, 2048          ; O_NONBLOCK (04000 octal = 2048 dec)
    syscall
    cmp rax, 0
    jl .proxy_err_pipe
    
    mov r8d, [cur_slot]
    mov eax, dword [rsp]
    mov [slot_proxy_pipe_r + r8*4], eax
    mov ecx, dword [rsp+4]
    mov [slot_proxy_pipe_w + r8*4], ecx
    
    ; HAProxy Pipe Size Boost (1MB = 1048576 = 0x100000 bytes)
    ; sys_fcntl(fd=pipe_w, F_SETPIPE_SZ=1031, cap=1048576)
    mov rax, 72            ; sys_fcntl
    mov rdi, rcx
    mov rsi, 1031          ; F_SETPIPE_SZ
    mov rdx, 1048576
    syscall
    add rsp, 16

.proxy_pipe_ready:
    mov r8d, [cur_slot]
    mov rsi, [slot_proxy_req_ptr + r8*8]
    mov edx, [slot_proxy_req_len + r8*4]
    call uring_submit_proxy_send_sqe
    jmp uring_cqe_continue

.proxy_sync_fail:
    ; Backend write failed → close everything and free slot
    mov r8d, [cur_slot]
    mov r13d, [slot_fds + r8*4]
    
    ; Close proxy fd
    mov r14d, [slot_proxy_fds + r8*4]
    cmp r14d, 0
    jle .psf_skip_fd
    mov rax, 3
    mov rdi, r14
    syscall
.psf_skip_fd:
    mov r8d, [cur_slot]
    
    ; Close pipes if allocated
    mov r10d, [slot_proxy_pipe_r + r8*4]
    test r10d, r10d
    jz .psf_skip_pipe_r
    mov rax, 3
    mov rdi, r10
    syscall
.psf_skip_pipe_r:
    mov r8d, [cur_slot]
    mov r11d, [slot_proxy_pipe_w + r8*4]
    test r11d, r11d
    jz .psf_skip_pipe_w
    mov rax, 3
    mov rdi, r11
    syscall
.psf_skip_pipe_w:
    mov r8d, [cur_slot]
    
    ; Cleanup state
    mov dword [slot_proxy_fds + r8*4], 0
    mov dword [slot_proxy_pipe_r + r8*4], 0
    mov dword [slot_proxy_pipe_w + r8*4], 0
    mov byte [slot_proxy_state + r8], 0
    
    jmp close_conn

.proxy_err_st2:
    jmp .proxy_fail

.proxy_err_pipe:
    add rsp, 16
    mov rax, 3
    mov rdi, r14           ; r14 holds the proxy socket that wasn't saved yet
    syscall
    jmp close_conn

.proxy_err_st1:
    mov r8d, dword [cur_slot]
    push rax               ; MUST PRESERVE RAX (error code) BEFORE close syscalls overwrite it!

    mov r10d, [slot_proxy_pipe_r + r8*4]
    cmp r10d, 0
    jle .err_st1_skip_r
    mov rax, 3
    mov rdi, r10
    syscall
.err_st1_skip_r:

    mov r11d, [slot_proxy_pipe_w + r8*4]
    cmp r11d, 0
    jle .err_st1_skip_w
    mov rax, 3
    mov rdi, r11
    syscall
.err_st1_skip_w:

    mov r14d, [slot_proxy_fds + r8*4]
    cmp r14d, 0
    jle .err_st1_skip_fd
    
    push r8
    call decrement_lb_meta
    pop r8
    
    mov rax, 3
    mov rdi, r14
    syscall
.err_st1_skip_fd:

    ; Ensures total slot sanitization
    mov dword [slot_proxy_fds + r8*4], 0
    mov dword [slot_proxy_pipe_r + r8*4], 0
    mov dword [slot_proxy_pipe_w + r8*4], 0
    
    pop rax                ; Restore original Connect error code into EAX
    jmp proxy_emit_502
.proxy_read_loop:
    ; 4. read from proxy_fd
    mov rax, 0          ; sys_read
    mov rdi, r14
    mov rsi, buffer
    mov rdx, 4096
    syscall
    cmp rax, 0
    jle .proxy_close
    mov r15, rax        ; bytes read
    
    ; 5. write to client_sock (r13)
    mov rsi, buffer
    mov rdx, r15
.proxy_write_loop:
    mov rax, 44         ; sys_sendto
    mov rdi, r13
    mov r10, 0x4000     ; MSG_NOSIGNAL
    xor r8, r8
    xor r9, r9
    syscall
    cmp rax, 0
    jle .proxy_close
    sub rdx, rax
    jz .proxy_read_loop
    add rsi, rax
    jmp .proxy_write_loop

.proxy_fail:
    mov rax, 44         ; sys_sendto
    mov rdi, r13        ; client_fd
    mov rsi, msg_502
    mov rdx, msg_502_len
    mov r10, 0x4000     ; MSG_NOSIGNAL
    xor r8, r8
    xor r9, r9
    syscall

.proxy_close:
    mov r8d, [cur_slot]
    push r8
    call decrement_lb_meta
    pop r8
    mov rax, 3          ; sys_close
    mov rdi, r14
    syscall
    push rax
    mov eax, dword [cur_slot]
    mov rsi, [slot_pipeline_next_req + rax*8]
    pop rax
    jmp read_request_parse_buffer_loop

.not_proxy:
    mov r8d, dword [cur_slot]
    cmp byte [slot_method + r8], 1
    ja send_405
.not_jit:
    ; === FAST PATH: Hash-table cache lookup ===
    ; rsi points to URI after "GET " (e.g., "/ ", "/about.html ")
    ; Use CRC32 hash With VHost Match
    mov r8d, dword [cur_slot]
    mov eax, [slot_vhost_id + r8*4]
    crc32 rax, qword [rsi]
    and rax, 0x3FF

    ; Lookup table cover
    lea rcx, [cache_table]
    shl rax, 6                 ; 64 bytes per entry
    add rcx, rax
    mov rdx, [rcx + 8]         ; hidden length
    test rdx, rdx
    jz .cache_miss              ; not hidden

    ; Verify URI key matches (collision guard)
    mov r10, [rsi]
    cmp r10, [rcx + 40]
    jne .cache_miss              ; hash collision → fallback to filesystem

    ; Cache HIT!
    ; === ETag / 304 Not Modified Check ===
    mov r8, rsi                 ; r8 = start of search (URI start)
    push rax
    mov eax, dword [cur_slot]
    mov r9, [slot_pipeline_next_req + rax*8]
    pop rax
    mov r10, [rcx + 16]         ; Load 8-byte hex ETag from cache

.scan_etag:
    mov r11, r8
    add r11, 16                 ; Need at least 16 bytes for checking
    cmp r11, r9
    jge .etag_not_found
    cmp byte [r8], 'I'
    je .etag_check_upper
    cmp byte [r8], 'i'
    je .etag_check_lower
    jmp .etag_next

.etag_check_upper:
    mov rax, 0x2D656E6F4E2D6649  ; “If-None-”
    cmp [r8], rax
    jne .etag_next
    jmp .etag_check_match

.etag_check_lower:
    mov rax, 0x2D656E6F6E2D6669  ; "if-none-"
    cmp [r8], rax
    jne .etag_next

.etag_check_match:
    ; We matched "If-None-" or "if-none-". Now check "Match:" or "match:"
    cmp dword [r8+8], 0x6374614D ; “Matt”
    je .match_h
    cmp dword [r8+8], 0x6374616D ; "matc"
    jne .etag_next

.match_h:
    cmp word [r8+12], 0x3A68   ; "h:"
    je .skip_spaces
    cmp word [r8+12], 0x3A68   ; wait: "h:" is 3A68.
    jne .etag_next

.skip_spaces:
    mov r11, r8
    add r11, 14
.space_loop:
    cmp byte [r11], ' '
    jne .check_quote
    inc r11
    jmp .space_loop

.check_quote:
    cmp byte [r11], '"'
    jne .etag_next

    ; Found the quote! The hex ETag is immediately after.
    inc r11
    mov r8, r11                 ; r8 now points EXACTLY to the 8 hex tanks!
    jmp .etag_found

.etag_next:
    inc r8
    jmp .scan_etag

.etag_found:
    mov rax, [r8]               ; Read the client's ETag value
    cmp rax, r10                ; Compare with our cached ETag hash (r10)
    jne .etag_not_found         ; Not match -> send 200 OK

    ; ETag matches! Send 304 Not Modified!
    mov rsi, msg_304
    mov rdx, msg_304_len
    jmp .cache_send_decision

.etag_not_found:
    mov rsi, [rcx]             ; cached response ptr
    ; rdx = cached length (already set via [rcx+8])

.cache_send_decision:
    ; ----------------------------------------------------
    ; PHASE 5 PIPELINE: Seed the Chunking & Sendfile state
    ; ----------------------------------------------------
    ; rsi = Memory Pointer (Headers + content if < 32KB)
    ; rdx = Memory Length 
    ; rcx = ptr to cache_table entry
    mov r11, [rcx + 24]        ; file_fd
    mov r12, [rcx + 32]        ; total_file_size

    ; But wait! For ETag 304, rcx is NOT the cache_table entry! rcx is anything!
    ; Actually, .tag_found jumps here. We must be extremely careful.
    
    cmp rsi, msg_304
    je .is_304_msg
    
    ; Normal Cache Hit Pipeline
    mov r8d, dword [cur_slot]
    
    ; Check HTML5 Range Request Offset
    mov r9, [slot_range_offset + r8*8]
    cmp r9, 0
    jg .is_206_msg

    mov [slot_mem_ptr + r8*8], rsi
    mov [slot_mem_remaining + r8*8], rdx

    cmp r12, 32768
    jg .enable_sendfile

    ; No sendfile needed (file is small, entirely in RAM)
    mov qword [slot_file_fd + r8*8], 0
    mov qword [slot_file_remaining + r8*8], 0
    jmp .head_check

.enable_sendfile:
    ; Sendfile needed!
    mov [slot_file_fd + r8*8], r11
    mov [slot_file_remaining + r8*8], r12
    
.head_check:
    cmp byte [slot_method + r8], 1 ; HEAD
    jne .dispatch_send
    
    ; Bypass file sending entirely and strip RAM body
    mov qword [slot_file_remaining + r8*8], 0
    ; Find \r\n\r\n to truncate rdx (memory length)
    mov r9, rsi
    add rdx, rsi
.head_scan:
    cmp rsi, rdx
    jge .head_done
    cmp dword [rsi], 0x0A0D0A0D
    je .head_found
    inc rsi
    jmp .head_scan
.head_found:
    add rsi, 4
.head_done:
    sub rsi, r9
    mov rdx, rsi    ; new length = headers only
    mov rsi, r9     ; restore original ptr
    mov [slot_mem_remaining + r8*8], rdx

    jmp .dispatch_send
    mov qword [slot_file_offset + r8*8], 0
    jmp .dispatch_send

.is_304_msg:
    ; ETag Hit (304 Not Modified)
    mov r8d, dword [cur_slot]
    mov [slot_mem_ptr + r8*8], rsi
    mov [slot_mem_remaining + r8*8], rdx
    mov qword [slot_file_fd + r8*8], 0
    mov qword [slot_file_remaining + r8*8], 0
    jmp .dispatch_send

.is_206_msg:
    ; Range bytes= START (r9), total (r12)
    cmp r9, r12
    jge send_416
    
    ; Determine END (r10)
    mov r10, [slot_range_end + r8*8]
    cmp r10, -1
    jne .check_end_bounds
    mov r10, r12
    dec r10
    jmp .end_bounded
.check_end_bounds:
    cmp r10, r12
    jl .end_bounded
    mov r10, r12
    dec r10
.end_bounded:
    
    push rcx            ; SAVE CACHE POINTER! (rep movsb clobbers rcx)
    
    mov eax, r8d
    shl rax, 8          ; rax = cur_slot * 256
    lea rdi, [slot_206_hdr + rax]
    mov r15, rdi        ; Save start
    
    mov rsi, hdr_206
    mov rcx, hdr_206_len
    rep movsb
    
    ; Content-Length: <r10 - START + 1>
    mov rax, r10
    sub rax, r9
    inc rax
    mov r14, rax   ; save length to send
    
    push r10
    push r8
    push r9
    push r11
    push r12
    call inline_itoa
    pop r12
    pop r11
    pop r9
    pop r8
    pop r10
    
    ; \r\nContent-Range: bytes
    mov rsi, str_cr_bytes
    mov rcx, str_cr_bytes_len
    rep movsb
    
    ; START
    mov rax, r9
    push r10
    push r8
    push r9
    push r11
    push r12
    call inline_itoa
    pop r12
    pop r11
    pop r9
    pop r8
    pop r10
    
    ; -
    mov byte [rdi], '-'
    inc rdi
    
    ; END (r10)
    mov rax, r10
    push r10
    push r8
    push r9
    push r11
    push r12
    call inline_itoa
    pop r12
    pop r11
    pop r9
    pop r8
    pop r10
    
    ; /
    mov byte [rdi], '/'
    inc rdi
    
    ; TOTAL
    mov rax, r12
    push r10
    push r8
    push r9
    push r11
    push r12
    call inline_itoa
    pop r12
    pop r11
    pop r9
    pop r8
    pop r10
    
    ; \r\n\r\n
    mov dword [rdi], 0x0A0D0A0D
    add rdi, 4
    
    ; Dispatch IO params
    mov [slot_mem_ptr + r8*8], r15
    mov rdx, rdi
    sub rdx, r15
    mov [slot_mem_remaining + r8*8], rdx
    
    pop rcx             ; RESTORE CACHE POINTER!
    
    mov r11, [rcx + 24]
    mov [slot_file_fd + r8*8], r11
    mov [slot_file_offset + r8*8], r9
    mov [slot_file_remaining + r8*8], r14

.dispatch_send:
    cmp byte [uring_enabled], 1
    jne .cache_sync_send
    mov r8d, [cur_slot]
    cmp r8d, 65535
    je .cache_sync_send
    ; Async SEND via io_uring
    mov rsi, [slot_mem_ptr + r8*8]
    mov rdx, [slot_mem_remaining + r8*8]
    ; If the memory buffer is huge (never happens anymore since >32KB is skipped, but just in case)
    cmp rdx, 32768
    jle .do_submit
    mov rdx, 32768
.do_submit:
    call uring_submit_send_sqe
    mov r8d, [cqe_saved_head]
    mov r15d, [cqe_saved_tail]
    jmp uring_cqe_continue
.cache_sync_send:
    mov r13, [legacy_client_fd] ; Restore client_fd (r13 was clobbered by vhost matching!)
    mov r8d, [cur_slot]
    mov rsi, [slot_mem_ptr + r8*8]
    mov rdx, [slot_mem_remaining + r8*8]
.cache_write_loop:
    mov rax, 44              ; sys_sendto
    mov rdi, r13
    mov r10, 0x4000          ; MSG_NOSIGNAL
    xor r8, r8
    xor r9, r9
    syscall
    cmp rax, 0
    jle close_conn             ; write error
    sub rdx, rax               ; remaining bytes
    jz .cache_write_done       ; all smells
    add rsi, rax               ; advance pointer
    jmp .cache_write_loop
.cache_write_done:
    ; Pipeline handle next request
    push rax
    mov eax, dword [cur_slot]
    mov rsi, [slot_pipeline_next_req + rax*8]
    pop rax
    jmp read_request_parse_buffer_loop

.cache_miss:
    push rax
    mov eax, dword [cur_slot]
    mov r9, [slot_pipeline_end_buf + rax*8]
    pop rax
    mov rdi, filepath
    
    ; --- FETCH VHOST-SPECIFIC DOC_ROOT ---
    mov r10d, dword [cur_slot]
    mov eax, [slot_vhost_id + r10*4]
    imul rax, 2048                       ; 2048 bytes per vhost entry
    lea r8, [vhosts + rax + 64]         ; doc_root starts at offset 64
.copy_root:
    mov al, [r8]
    test al, al                         ; check for null terminator
    jz .copy_root_done
    mov [rdi], al
    inc rdi
    inc r8
    jmp .copy_root
.copy_root_done:
    mov [filepath_root_end], rdi  ; Save doc_root end position for auto-index guard

    ; --- AVX PARSING BYPASS ---
    cmp byte [avx512_enabled], 1
    je avx512_parsing
    cmp byte [avx2_enabled], 1
    je avx2_parsing

copy_path:
    cmp rsi, r9    ; End of data read?
    jge end_path
    
    mov al, [rsi]
    cmp al, 0x20   ; ' '
    je end_path
    cmp al, 0x3F   ; '?'
    je end_path
    cmp al, 13     ; CR
    je end_path
    cmp al, 10     ; LF
    je end_path
    cmp al, 0
    je end_path
    
    mov [rdi], al
    inc rdi
    inc rsi
    
    ; Protection against filepath overflow (max 1024)
    mov rax, filepath
    add rax, 1000
    cmp rdi, rax
    jge end_path
    
    jmp copy_path

avx512_parsing:
    ; Broadcast delimiter bytes to ZMMs
    vpbroadcastb zmm1, byte [char_space]
    vpbroadcastb zmm2, byte [char_qmark]
    vpbroadcastb zmm3, byte [char_cr]
    vpbroadcastb zmm4, byte [char_lf]
    vpbroadcastb zmm5, byte [char_nul]

.avx_loop:
    mov rax, r9
    sub rax, rsi
    cmp rax, 64
    jl copy_path   ; If there are less than 64 bytes left, we use standard parsing

    ; Load 64 bytes of URL structure
    vmovdqu8 zmm0, [rsi]

    ; Parallel comparison on 64 bytes
    vpcmpb k1, zmm0, zmm1, 0  ; equal
    vpcmpb k2, zmm0, zmm2, 0
    vpcmpb k3, zmm0, zmm3, 0
    vpcmpb k4, zmm0, zmm4, 0
    vpcmpb k5, zmm0, zmm5, 0

    ; Combine masks efficiently
    kmovq rax, k1
    kmovq rcx, k2
    or rax, rcx
    kmovq rcx, k3
    or rax, rcx
    kmovq rcx, k4
    or rax, rcx
    kmovq rcx, k5
    or rax, rcx

    test rax, rax
    jz .no_match

    ; Match found!
    tzcnt rcx, rax   ; First matching byte index

    ; Bounds check before copy
    mov rax, filepath
    add rax, 1000
    sub rax, rdi
    cmp rcx, rax
    jle .do_copy
    mov rcx, rax

.do_copy:
    ; Copy EXACTLY the URL part (multipled reading speed via vectorized scan)
    rep movsb
    jmp end_path

.no_match:
    ; No delimiter found, write directly using vectorized instructions
    vmovdqu8 [rdi], zmm0
    add rsi, 64
    add rdi, 64
    
    mov rax, filepath
    add rax, 1000
    cmp rdi, rax
    jge end_path
    
    jmp .avx_loop

avx2_parsing:
    ; Broadcast delimiter bytes to YMMs
    vpbroadcastb ymm10, byte [char_space]
    vpbroadcastb ymm11, byte [char_qmark]
    vpbroadcastb ymm12, byte [char_cr]
    vpbroadcastb ymm13, byte [char_lf]
    vpbroadcastb ymm14, byte [char_nul]

.avx2_loop:
    mov rax, r9
    sub rax, rsi
    cmp rax, 32
    jl copy_path   ; If there are less than 32 bytes remaining, we use standard parsing

    ; Load 32 bytes of URL structure
    vmovdqu ymm0, [rsi]

    ; Parallel comparison on 32 bytes
    vpcmpeqb ymm1, ymm0, ymm10
    vpmovmskb eax, ymm1
    
    vpcmpeqb ymm2, ymm0, ymm11
    vpmovmskb ecx, ymm2
    or eax, ecx

    vpcmpeqb ymm3, ymm0, ymm12
    vpmovmskb ecx, ymm3
    or eax, ecx

    vpcmpeqb ymm4, ymm0, ymm13
    vpmovmskb ecx, ymm4
    or eax, ecx

    vpcmpeqb ymm5, ymm0, ymm14
    vpmovmskb ecx, ymm5
    or eax, ecx

    test eax, eax
    jz .avx2_no_match

    ; Match found!
    tzcnt ecx, eax   ; First matching byte index

    ; Bounds check before copy
    mov rax, filepath
    add rax, 1000
    sub rax, rdi
    cmp rcx, rax
    jle .avx2_do_copy
    mov rcx, rax

.avx2_do_copy:
    ; Copy EXACTLY the URL part
    rep movsb
    jmp end_path

.avx2_no_match:
    ; No delimiter found, write directly using vectorized instructions
    vmovdqu [rdi], ymm0
    add rsi, 32
    add rdi, 32
    
    mov rax, filepath
    add rax, 1000
    cmp rdi, rax
    jge end_path
    
    jmp .avx2_loop

end_path:
    mov byte [rdi], 0
    
    cmp rdi, filepath
    jle save_filepath_end
    
    cmp byte [rdi - 1], '/'
    jne save_filepath_end
    ; Only auto-index if the '/' came from the URL (not the doc_root trailing slash)
    cmp rdi, [filepath_root_end]
    jle save_filepath_end          ; URL parser added 0 bytes → not a directory request
    
    ; --- Dynamic Auto-Indexation ---
    mov r10, rdi               ; save original end pointer
    xor r15, r15               ; index loop counter
.index_loop:
    mov r8d, dword [cur_slot]
    mov eax, [slot_vhost_id + r8*4]
    imul rax, 2048
    lea r8, [vhosts + rax]
    
    movzx ecx, word [r8 + 896] ; index_count
    cmp r15, rcx
    jge .idx_fail
    
    mov rax, r15
    imul rax, 24
    lea r9, [r8 + 904 + rax]   ; pointer to index_files[r15]
    
    mov rdi, r10               ; restore rdi
.idx_copy:
    mov cl, [r9]
    test cl, cl
    jz .idx_copy_done
    mov [rdi], cl
    inc rdi
    inc r9
    jmp .idx_copy
.idx_copy_done:
    mov byte [rdi], 0
    
    push rcx
    push r10
    mov rdi, filepath
    mov rax, 2
    mov rsi, 0
    mov rdx, 0
    syscall
    pop r10
    pop rcx
    
    cmp rax, 0
    jge .idx_success
    
    inc r15
    jmp .index_loop
    
.idx_fail:
    jmp save_filepath_end

.idx_success:
    mov [file_fd], rax
    jmp open_file_success

save_filepath_end:
    ; CRITICAL FIX: Saving end of string pointer in r14
    ; before rdi is overwritten by future system calls.
    mov r14, rdi        

open_file:
    ; 7. sys_open
    mov rdi, filepath
open_file_with_rdi:
    mov rax, 2
    mov rsi, 0
    mov rdx, 0
    syscall

    cmp rax, 0
    jl send_404

    mov [file_fd], rax

open_file_success:
    ; 8. sys_fstat (necessary for Content-Length keep-alive)
    mov rax, 5
    mov rdi, [file_fd]
    mov rsi, stat_buf
    syscall
    mov r15, [stat_buf + 48] ; st_size

    ; RANGE REQUEST CHECK
    mov r8d, dword [cur_slot]
    mov r9, [slot_range_offset + r8*8]
    cmp r9, 0
    jg .build_206_hdr
    mov r10, [slot_range_end + r8*8]
    cmp r10, -1
    jne .build_206_hdr

    ; 9. MIME type + Build dynamic keep-alive header with Content-Length
    ; r14 points to the NULL byte, r14-4 contains the last 4 characters
    mov eax, [r14 - 4]
    cmp eax, 0x7373632e ; ".css"
    je .build_css_hdr

.build_html_hdr:
    ; Copy HTML header prefix to resp_hdr
    mov rsi, hdr_ka_html
    mov rdi, resp_hdr
    mov rcx, hdr_ka_html_len
    rep movsb
    jmp .append_content_length

.build_css_hdr:
    ; Copy CSS header prefix to resp_hdr
    mov rsi, hdr_ka_css
    mov rdi, resp_hdr
    mov rcx, hdr_ka_css_len
    rep movsb

.append_content_length:
    ; itoa: convert r15 (file_size) to ASCII at rdi
    mov rax, r15
    lea r8, [itoa_buf + 20]
    mov byte [r8], 0
    mov rcx, 0xCCCCCCCCCCCCCCCD
.itoa_loop:
    dec r8
    mov r9, rax
    mul rcx
    shr rdx, 3
    lea r10, [rdx + rdx*4]
    add r10, r10
    sub r9, r10
    add r9b, '0'
    mov [r8], r9b
    mov rax, rdx
    test rax, rax
    jnz .itoa_loop
    ; Copy ASCII number to resp_hdr
.copy_num:
    mov al, [r8]
    test al, al
    jz .num_done
    mov [rdi], al
    inc rdi
    inc r8
    jmp .copy_num
.num_done:
    ; Append \r\n\r\n
    mov dword [rdi], 0x0A0D0A0D  ; \r\n\r\n in little-endian
    add rdi, 4
    ; rdi = end of header, calculate length
    mov rdx, rdi
    sub rdx, resp_hdr           ; rdx = total header length

    ; Send header
    mov rax, 1                  ; sys_write
    mov rdi, r13
    mov rsi, resp_hdr
    ; rdx already set
    syscall
    jmp send_file_content

.build_206_hdr:
    cmp r9, r15
    jge send_416
    
    mov r10, [slot_range_end + r8*8]
    cmp r10, -1
    jne .check_end_bounds
    mov r10, r15
    dec r10
    jmp .end_bounded
.check_end_bounds:
    cmp r10, r15
    jl .end_bounded
    mov r10, r15
    dec r10
.end_bounded:

    mov rsi, hdr_206
    mov rdi, resp_hdr
    mov rcx, hdr_206_len
    rep movsb
    
    mov rax, r10
    sub rax, r9
    inc rax
    mov r12, rax    ; r12 = bytes_to_send (count)
    
    push r10
    push r8
    push r9
    push r11
    push r12
    call inline_itoa
    pop r12
    pop r11
    pop r9
    pop r8
    pop r10
    
    mov rsi, str_cr_bytes
    mov rcx, str_cr_bytes_len
    rep movsb
    
    ; START
    mov rax, r9
    push r10
    push r8
    push r9
    push r11
    push r12
    call inline_itoa
    pop r12
    pop r11
    pop r9
    pop r8
    pop r10
    
    mov byte [rdi], '-'
    inc rdi
    
    ; END
    mov rax, r10
    push r10
    push r8
    push r9
    push r11
    push r12
    call inline_itoa
    pop r12
    pop r11
    pop r9
    pop r8
    pop r10
    
    mov byte [rdi], '/'
    inc rdi
    
    ; TOTAL
    mov rax, r15
    push r10
    push r8
    push r9
    push r11
    push r12
    call inline_itoa
    pop r12
    pop r11
    pop r9
    pop r8
    pop r10
    
    ; \r\n\r\n
    mov dword [rdi], 0x0A0D0A0D
    add rdi, 4
    
    ; send header
    mov rdx, rdi
    sub rdx, resp_hdr
    mov rax, 1
    mov rdi, r13
    mov rsi, resp_hdr
    syscall
    
    jmp send_file_content_range

send_404:
    mov rax, 1
    mov rdi, r13
    mov rsi, hdr_404
    mov rdx, hdr_404_len
    syscall
    jmp close_conn

send_405:
    mov rax, 1
    mov rdi, r13
    mov rsi, hdr_405
    mov rdx, hdr_405_len
    syscall
    jmp close_conn

send_416:
    mov rax, 1
    mov rdi, r13
    mov rsi, hdr_416
    mov rdx, hdr_416_len
    syscall
    jmp close_conn

inline_itoa:
    lea rsi, [itoa_buf + 20]
    mov byte [rsi], 0
    mov r10, 0xCCCCCCCCCCCCCCCD
.idiv:
    dec rsi
    mov rcx, rax
    mul r10
    shr rdx, 3
    lea r8, [rdx + rdx*4]
    add r8, r8
    sub rcx, r8
    add cl, '0'
    mov [rsi], cl
    mov rax, rdx
    test rax, rax
    jnz .idiv
.icpy:
    mov al, [rsi]
    test al, al
    jz .iend
    mov [rdi], al
    inc rdi
    inc rsi
    jmp .icpy
.iend:
    ret

send_file_content:
    mov r8d, dword [cur_slot]
    cmp byte [slot_method + r8], 1 ; HEAD
    je send_file_cork_off
    
    cmp byte [tcp_nopush_enabled], 1
    jne .skip_cork_on
    ; TCP_CORK ON (combine header + sendfile in 1 TCP segment)
    mov rax, 54
    mov rdi, r13
    mov rsi, 6              ; SOL_TCP
    mov rdx, 3              ; TCP_CORK
    mov r10, cork_on
    mov r8, 4
    syscall
.skip_cork_on:

    ; 10. sys_sendfile
    mov rax, 40
    mov rdi, r13
    mov rsi, [file_fd]
    mov rdx, 0
    mov r10, r15
    syscall
    jmp send_file_cork_off

send_file_content_range:
    mov r8d, dword [cur_slot]
    cmp byte [slot_method + r8], 1 ; HEAD
    je send_file_cork_off
    
    lea rdx, [slot_range_offset + r8*8]
    mov r10, r12
    mov rax, 40
    mov rdi, r13
    mov rsi, [file_fd]
    syscall

send_file_cork_off:
    cmp byte [tcp_nopush_enabled], 1
    jne .skip_cork_off
    ; TCP_CORK OFF (flush the combined segment)
    mov rax, 54
    mov rdi, r13
    mov rsi, 6
    mov rdx, 3
    mov r10, cork_off
    mov r8, 4
    syscall
.skip_cork_off:

    ; 11. sys_close(file_fd)
    mov rax, 3
    mov rdi, [file_fd]
    syscall

    ; === KEEP-ALIVE: pipeline ===
    push rax
    mov eax, dword [cur_slot]
    mov rsi, [slot_pipeline_next_req + rax*8]
    pop rax
    jmp read_request_parse_buffer_loop

uring_keepalive_loop:
    cmp dword [cur_slot], 65535
    je close_conn
    ; io_uring: submit async READ for next keep-alive request
    ; Uses the current slot (cur_slot) for the buffer
    mov r8d, [cur_slot]
    call uring_submit_read_sqe
    ; Restore CQE state and continue batch
    mov r8d, [cqe_saved_head]
    mov r15d, [cqe_saved_tail]
    jmp uring_cqe_continue

close_conn:
    cmp byte [uring_enabled], 1
    je .uring_close

    ; Non-uring: close client socket
    mov r13, [legacy_client_fd]
    mov rax, 3             ; sys_close
    mov rdi, r13
    syscall
    jmp accept_loop

.uring_close:
    ; Free the slot if we have one
    mov eax, [cur_slot]
    cmp eax, 65535
    je .uring_close_no_slot
    
    ; Ensure slot is not double-freed! (Fix for slot_top corruption / Segfault)
    cmp dword [slot_fds + rax*4], -1
    je .uring_close_no_slot
    ; Free slot
    mov ecx, [slot_top]
    mov [slot_free + rcx*4], eax
    inc dword [slot_top]
    mov dword [cur_slot], 65535
.uring_close_no_slot:
    ; Submit IORING_OP_CLOSE asynchronous (Client Socket)
    push r8
    mov rcx, [sq_ring]
    mov ebx, [uring_params + 44]
    mov edx, [rcx + rbx]
    mov r8d, edx
    mov ebx, [uring_params + 48]
    and r8d, [rcx + rbx]
    mov ebx, [uring_params + 64]
    lea rbx, [rcx + rbx]
    mov [rbx + r8 * 4], r8d
    mov r9, [sqes]
    mov r10d, r8d
    shl r10, 6
    add r9, r10
    pxor xmm0, xmm0
    movdqu [r9], xmm0
    movdqu [r9+16], xmm0
    movdqu [r9+32], xmm0
    movdqu [r9+48], xmm0
    pop r8
    mov byte [r9], 19             ; IORING_OP_CLOSE
    mov dword [r9 + 4], r13d
    mov qword [r9 + 32], 0xDEAD  ; user_data sentinel
    inc edx
    mov rcx, [sq_ring]
    mov ebx, [uring_params + 44]
    mov [rcx + rbx], edx
    
    ; Also close Pipeline pipes if proxy mode!
    mov eax, [cur_slot]
    cmp eax, 65535
    je .skip_proxy_pipe_close
    mov r10d, [slot_proxy_pipe_r + rax*4]
    cmp r10d, 0
    jle .skip_proxy_pipe_close
    
    ; synchronous sys_close is fine for backend cleanup during disconnect
    push rax
    push rdi
    mov rdi, r10
    mov rax, 3
    syscall
    
    mov eax, [cur_slot]
    mov edi, [slot_proxy_pipe_w + rax*4]
    mov rax, 3
    syscall
    
    mov eax, [cur_slot]
    mov edi, [slot_proxy_fds + rax*4]
    cmp edi, 0
    jle .skip_proxy_fd_close
    
    mov r8d, eax
    push rax
    call decrement_lb_meta
    pop rax
    
    mov rdi, [slot_proxy_fds + rax*4]
    mov eax, 3
    syscall
    
    mov eax, [cur_slot]
    mov dword [slot_proxy_fds + rax*4], 0
    mov dword [slot_proxy_pipe_r + rax*4], 0
    mov dword [slot_proxy_pipe_w + rax*4], 0
.skip_proxy_fd_close:
    pop rdi
    pop rax
.skip_proxy_pipe_close:

    ; Multi-shot: no need to re-submit accept. Continue batch EQC.
    mov r8d, [cqe_saved_head]
    mov r15d, [cqe_saved_tail]
    jmp uring_cqe_continue

; ====================================================================
; OPTIMIZED IO_URING — Keep-Alive + Pipeline ACCEPTs + Batch CQE
; ====================================================================

; --- Subroutine: Submit 1 ACCEPT SQE ---
uring_submit_one_accept:
    push r8
    mov rcx, [sq_ring]
    mov ebx, [uring_params + 44]
    mov edx, [rcx + rbx]
    mov r8d, edx
    mov ebx, [uring_params + 48]
    and r8d, [rcx + rbx]
    mov ebx, [uring_params + 64]
    lea rbx, [rcx + rbx]
    mov [rbx + r8 * 4], r8d
    mov r9, [sqes]
    mov r10d, r8d
    shl r10, 6
    add r9, r10
    pxor xmm0, xmm0
    movdqu [r9], xmm0
    movdqu [r9+16], xmm0
    movdqu [r9+32], xmm0
    movdqu [r9+48], xmm0
    pop r8
    mov byte [r9], 13             ; IORING_OP_ACCEPT
    mov word [r9 + 2], 1          ; ioprio = IORING_ACCEPT_MULTISHOT
    mov dword [r9 + 4], r12d
    ; accept_flags: offset 28 left at 0 (blocking sockets, sync read works)
    mov rax, 12                   ; type = 12 (ACCEPT)
    shl rax, 16
    movzx r10d, word [bound_ports + r15*2]
    or rax, r10                   ; merge network port into low 16 bits
    mov qword [r9 + 32], rax      ; user_data = (12 << 16) | port
    lea r10, [client_addr_len]
    mov qword [r9 + 8], r10
    lea r10, [client_addr]
    mov qword [r9 + 16], r10
    inc edx
    mov rcx, [sq_ring]
    mov ebx, [uring_params + 44]
    mov [rcx + rbx], edx
    ret

; --- Subroutine: Submit POLL_ADD SQE for sys_sendfile (EAGAIN) ---
; Input: r8d = slot index, r13 = client fd
; Preserves: r12, r13, r14, r15
uring_submit_poll_add_sqe:
    push r8
    mov rcx, [sq_ring]
    mov ebx, [uring_params + 44]
    mov edx, [rcx + rbx]
    mov r8d, edx
    mov ebx, [uring_params + 48]
    and r8d, [rcx + rbx]
    mov ebx, [uring_params + 64]
    lea rbx, [rcx + rbx]
    mov [rbx + r8 * 4], r8d
    mov r9, [sqes]
    mov r10d, r8d
    shl r10, 6
    add r9, r10
    pxor xmm0, xmm0
    movdqu [r9], xmm0
    movdqu [r9+16], xmm0
    movdqu [r9+32], xmm0
    movdqu [r9+48], xmm0
    pop r8
    mov byte [r9], 6              ; IORING_OP_POLL_ADD
    mov dword [r9 + 4], r13d      ; fd = client
    mov dword [r9 + 28], 4        ; poll32_events = POLLOUT (4)
    
    ; user_data = 0x40000 + slot_idx (type 4 = POLL_ADD)
    mov eax, r8d
    add eax, 0x40000
    mov qword [r9 + 32], rax
    
    mov ebx, [uring_params + 44]
    mov edx, [rcx + rbx]
    inc edx
    mov [rcx + rbx], edx
    pop rbp
    ret

; --- Subroutine: Submit READ SQE for keep-alive ---
; Input: r8d = slot index, r13 = client fd
; Preserves: r12, r13, r14, r15
uring_submit_read_sqe:
    push r8
    mov rcx, [sq_ring]
    mov ebx, [uring_params + 44]
    mov edx, [rcx + rbx]
    mov r8d, edx
    mov ebx, [uring_params + 48]
    and r8d, [rcx + rbx]
    mov ebx, [uring_params + 64]
    lea rbx, [rcx + rbx]
    mov [rbx + r8 * 4], r8d
    mov r9, [sqes]
    mov r10d, r8d
    shl r10, 6
    add r9, r10
    pxor xmm0, xmm0
    movdqu [r9], xmm0
    movdqu [r9+16], xmm0
    movdqu [r9+32], xmm0
    movdqu [r9+48], xmm0
    pop r8
    mov byte [r9], 22             ; IORING_OP_READ (standard, sockets need offset=-1)
    mov dword [r9 + 4], r13d     ; fd = client
    mov qword [r9 + 8], -1       ; offset = -1 (socket, mandatory)
    ; Buffer = conn_pool + slot * 4096
    mov eax, r8d
    shl eax, 12                   ; slot*4096
    add rax, [conn_pool]
    mov qword [r9 + 16], rax     ; buffer addr
    mov dword [r9 + 24], 4096    ; len
    ; user_data = 0x10000 + slot_idx (type 1 = READ)
    mov eax, r8d
    add eax, 0x10000
    mov qword [r9 + 32], rax
    ; Store client fd in slot_fds
    mov eax, r8d
    mov [slot_fds + rax*4], r13d
    push r8
    mov rcx, [sq_ring]
    mov ebx, [uring_params + 44]
    inc edx
    mov [rcx + rbx], edx
    pop r8
    ret

; --- Subroutine: Submit PROXY READ SQE ---
; Input: r8d = slot index, r14d = proxy fd
uring_submit_proxy_read_sqe:
    push r8
    mov rcx, [sq_ring]
    mov ebx, [uring_params + 44]
    mov edx, [rcx + rbx]          ; SQ tail
    mov r8d, edx
    mov ebx, [uring_params + 48]
    and r8d, [rcx + rbx]          ; mask
    mov ebx, [uring_params + 64]
    lea rbx, [rcx + rbx]
    mov [rbx + r8 * 4], r8d       ; SQ array entry
    mov r9, [sqes]
    mov r10d, r8d
    shl r10, 6
    add r9, r10                    ; r9 = SQE pointer
    pxor xmm0, xmm0
    movdqu [r9], xmm0
    movdqu [r9+16], xmm0
    movdqu [r9+32], xmm0
    movdqu [r9+48], xmm0
    pop r8
    
    mov byte [r9], 22             ; IORING_OP_READ
    mov dword [r9 + 4], r14d      ; fd = proxy_fd
    mov qword [r9 + 8], -1        ; offset = -1
    
    ; Buffer = conn_pool + slot * 4096
    mov eax, r8d
    shl eax, 12                   ; slot*4096
    add rax, [conn_pool]
    mov qword [r9 + 16], rax      ; buffer addr
    mov dword [r9 + 24], 4096     ; len
    
    ; user_data = 0x30000 + slot (type 3 = PROXY READ)
    mov eax, r8d
    add eax, 0x30000
    mov qword [r9 + 32], rax
    
    push r8
    mov rcx, [sq_ring]
    mov ebx, [uring_params + 44]
    inc edx
    mov [rcx + rbx], edx
    pop r8
    ret
; ==============================================================
; PROXY CONNECTION POOL — Subroutines
; ==============================================================

decrement_lb_meta:
    ; input: r8d = cur_slot
    ; clobbers: rax, rcx, rdx
    movzx eax, word [slot_proxy_lb_meta + r8*2]
    test eax, eax
    jz .dec_lb_done
    
    mov rcx, rax
    shr rcx, 8          ; rcx = upstream_id
    and rax, 0xFF       ; rax = server_id
    
    imul rcx, 1904
    lea rdx, [upstreams_list]   ; Need separate lea from relative displacement
    add rcx, rdx
    
    cmp dword [rcx + 36], 2     ; algorithm == least_conn
    jne .dec_lb_clear

    lock sub qword [rcx + 1776 + rax*8], 1

.dec_lb_clear:
    mov word [slot_proxy_lb_meta + r8*2], 0
.dec_lb_done:
    ret


; proxy_pool_acquire: Pop a ready backend fd from the pool.
; Uses cur_slot to find loc_index and pops from proxy_pool_stacks[loc_index]
; Returns: edi = fd (>= 0) or edi = -1 if pool empty.
; Clobbers: rax, rcx, rdx, r8, r9
proxy_pool_acquire:
    mov ecx, [cur_slot]
    mov edx, [slot_proxy_loc_idx + rcx*4]  ; edx = id_route
    mov eax, [proxy_pool_tops + rdx*4]
    test eax, eax
    jz .pool_acq_empty
    dec eax
    mov [proxy_pool_tops + rdx*4], eax

    ; Array offset: proxy_pool_stacks + (id_route * 1024) + (eax * 4)
    mov r8, rdx
    shl r8, 10
    lea r9, [proxy_pool_stacks + r8]
    mov edi, [r9 + rax*4]
    ret
.pool_acq_empty:
    mov edi, -1
    ret

proxy_pool_release:
    ; (No LB modifications here because proxy connections exist seamlessly)

    mov ecx, [cur_slot]
    mov edx, [slot_proxy_loc_idx + rcx*4]  ; edx = id_route
    mov eax, [proxy_pool_tops + rdx*4]
    cmp eax, [proxy_pool_size_global]
    jge .pool_rel_full

    ; Array offset: proxy_pool_stacks + (id_route * 1024) + (eax * 4)
    mov r8, rdx
    shl r8, 10
    lea r9, [proxy_pool_stacks + r8]
    mov [r9 + rax*4], edi

    inc eax
    mov [proxy_pool_tops + rdx*4], eax
    ret
.pool_rel_full:
    ; Pool full — close the excess fd
    push rdi
    mov rax, 3                 ; sys_close
    syscall
    pop rdi
    ret

; proxy_pool_create_one: Create a new UNIX socket connection for the pool.
; Uses cached sockaddr from proxy_pool_addr.
; Returns: eax = fd (>= 0) or eax = -1 on failure.
; Clobbers: rdi, rsi, rdx, rcx, r10, r11
proxy_pool_create_one:
    ; socket(Family, SOCK_STREAM, 0)
    mov rax, 41
    movzx rdi, word [proxy_pool_addr]  ; Load AF_UNIX or AF_INET dynamically
    mov rsi, 1                 ; SOCK_STREAM
    xor rdx, rdx
    syscall
    cmp eax, 0
    jl .pool_create_fail

    ; Connect
    mov edi, eax               ; fd
    push rdi                   ; save fd

    ; ---- AF_INET TCP_NODELAY Optimization ----
    movzx ecx, word [proxy_pool_addr]
    cmp ecx, 2                 ; AF_INET
    jne .skip_nodelay
    push 1
    mov rax, 54                ; sys_setsockopt
    ; rdi already has fd
    mov rsi, 6                 ; IPPROTO_TCP
    mov rdx, 1                 ; TCP_NODELAY
    mov r10, rsp               ; pointer to integer 1
    mov r8, 4                  ; sizeof(int)
    syscall
    add rsp, 8
.skip_nodelay:
    ; ------------------------------------------

    mov rax, 42                ; sys_connect
    lea rsi, [proxy_pool_addr]
    mov edx, [proxy_pool_addrlen]
    syscall
    pop rdi                    ; restore fd
    cmp eax, 0
    jl .pool_create_close

    mov eax, edi               ; return fd in eax
    ret

.pool_create_close:
    ; Connect failed — close the socket
    push rax                   ; save error code
    mov rax, 3
    ; rdi still has fd
    syscall
    pop rax
.pool_create_fail:
    mov eax, -1
    ret

; --- Subroutine: Submit PROXY CONNECT SQE ---
; Input: r8d = slot index
uring_submit_proxy_connect_sqe:
    push r8
    mov rcx, [sq_ring]
    mov ebx, [uring_params + 44]
    mov edx, [rcx + rbx]          ; SQ tail
    mov r8d, edx
    mov ebx, [uring_params + 48]
    and r8d, [rcx + rbx]          ; mask
    mov ebx, [uring_params + 64]
    lea rbx, [rcx + rbx]
    mov [rbx + r8 * 4], r8d       ; SQ array entry
    mov r9, [sqes]
    mov r10d, r8d
    shl r10, 6
    add r9, r10                    ; r9 = SQE pointer
    pxor xmm0, xmm0
    movdqu [r9], xmm0
    movdqu [r9+16], xmm0
    movdqu [r9+32], xmm0
    movdqu [r9+48], xmm0
    pop r8
    
    mov byte [r9], 16             ; IORING_OP_CONNECT
    mov r14d, [slot_proxy_fds + r8*4]
    mov dword [r9 + 4], r14d      ; fd = proxy_fd
    
    ; sockaddr address: slot_proxy_sockaddr + slot*110
    mov eax, r8d
    imul eax, eax, 110
    lea r10, [slot_proxy_sockaddr + rax]
    mov qword [r9 + 16], r10      ; addr = sockaddr_un ptr
    mov qword [r9 + 8], 0         ; offset
    
    ; Compute EXACT addrlen = 2 (family) + strlen(sun_path) + 1 (null byte)
    lea rdi, [r10 + 2]            ; sun_path
    xor ecx, ecx
.strlen_loop:
    mov al, [rdi + rcx]
    cmp al, 0
    je .strlen_done
    inc ecx
    jmp .strlen_loop
.strlen_done:
    add ecx, 3                    ; +2 for sa_family, +1 for NULL terminator
    mov dword [r9 + 24], ecx      ; len = EXACT addrlen
    
    ; user_data = 0x50000 + slot (type 5 = PROXY CONNECT)
    mov eax, r8d
    add eax, 0x50000
    mov qword [r9 + 32], rax
    
    push r8
    mov rcx, [sq_ring]
    mov ebx, [uring_params + 44]
    inc edx
    mov [rcx + rbx], edx
    pop r8
    ret

; --- Subroutine: Submit PROXY SEND SQE ---
; Input: r8d = slot index, rsi = buffer, edx = length
uring_submit_proxy_send_sqe:
    push r8
    push rdx
    push rsi
    mov rcx, [sq_ring]
    mov ebx, [uring_params + 44]
    mov edx, [rcx + rbx]          ; SQ tail
    mov r8d, edx
    mov ebx, [uring_params + 48]
    and r8d, [rcx + rbx]          ; mask
    mov ebx, [uring_params + 64]
    lea rbx, [rcx + rbx]
    mov [rbx + r8 * 4], r8d       ; SQ array entry
    mov r9, [sqes]
    mov r10d, r8d
    shl r10, 6
    add r9, r10                    ; r9 = SQE pointer
    pxor xmm0, xmm0
    movdqu [r9], xmm0
    movdqu [r9+16], xmm0
    movdqu [r9+32], xmm0
    movdqu [r9+48], xmm0
    pop rsi
    pop rdx
    pop r8
    
    ; Opcode fallback: The Kernel returned -EINVAL on SEND_ZC (39).
    ; Falling back to stable ASYNC SEND (26) for both families to prevent timeouts.
    push rdx
    mov eax, 110
    mul r8d
    lea r10, [slot_proxy_sockaddr + rax]
    pop rdx
    movzx ebx, word [r10]
    cmp ebx, 2          ; AF_INET
    jne .use_send_normal
    mov byte [r9], 26   ; IORING_OP_SEND (was 39 ZC, but kernel rejected it with -EINVAL)
    jmp .send_op_set
.use_send_normal:
    mov byte [r9], 26   ; IORING_OP_SEND
.send_op_set:
    mov r14d, [slot_proxy_fds + r8*4]
    mov dword [r9 + 4], r14d      ; fd = proxy_fd
    mov qword [r9 + 16], rsi      ; addr = buffer ptr
    mov dword [r9 + 24], edx      ; len
    mov dword [r9 + 28], 0x4000   ; send_flags = MSG_NOSIGNAL
    
    ; user_data = 0x60000 + slot (type 6 = PROXY SEND)
    mov eax, r8d
    add eax, 0x60000
    mov qword [r9 + 32], rax
    
    push r8
    mov rcx, [sq_ring]
    mov ebx, [uring_params + 44]
    mov edx, [rcx + rbx]          ; Fix: Re-read sq_tail because edx held len!
    inc edx
    mov [rcx + rbx], edx
    pop r8
    ret

; --- Subroutine: Submit POLL_ADD SQE for PROXY SOCKET (POLLIN) ---
; Waits for Node.js to reply before submitting blocking SPLICE_IN.
; Input: r8d = slot index
uring_submit_proxy_poll_sqe:
    push r8
    mov rcx, [sq_ring]
    mov ebx, [uring_params + 44]
    mov edx, [rcx + rbx]
    mov r8d, edx
    mov ebx, [uring_params + 48]
    and r8d, [rcx + rbx]
    mov ebx, [uring_params + 64]
    lea rbx, [rcx + rbx]
    mov [rbx + r8 * 4], r8d
    mov r9, [sqes]
    mov r10d, r8d
    shl r10, 6
    add r9, r10
    pxor xmm0, xmm0
    movdqu [r9], xmm0
    movdqu [r9+16], xmm0
    movdqu [r9+32], xmm0
    movdqu [r9+48], xmm0
    pop r8
    
    mov byte [r9], 6              ; IORING_OP_POLL_ADD
    mov eax, [slot_proxy_fds + r8*4]
    mov dword [r9 + 4], eax       ; fd = proxy socket
    mov dword [r9 + 28], 1        ; poll32_events = POLLIN (1)
    
    ; user_data = 0x90000 + slot_idx (type 9 = PROXY POLL)
    mov eax, r8d
    add eax, 0x90000
    mov qword [r9 + 32], rax
    
    push r8
    mov rcx, [sq_ring]
    mov ebx, [uring_params + 44]
    mov edx, [rcx + rbx]
    inc edx
    mov [rcx + rbx], edx
    pop r8
    ret

; --- Subroutine: Submit PROXY SPLICE IN SQE (Node -> Pipe_W) ---
; Input: r8d = slot index, r15d = bytes to splice
uring_submit_proxy_splice_in_sqe:
    push r8
    mov rcx, [sq_ring]
    mov ebx, [uring_params + 44]
    mov edx, [rcx + rbx]          ; SQ tail
    mov r8d, edx
    mov ebx, [uring_params + 48]
    and r8d, [rcx + rbx]          ; mask
    mov ebx, [uring_params + 64]
    lea rbx, [rcx + rbx]
    mov [rbx + r8 * 4], r8d       ; SQ array entry
    mov r9, [sqes]
    mov r10d, r8d
    shl r10, 6
    add r9, r10                    ; r9 = SQE pointer
    pxor xmm0, xmm0
    movdqu [r9], xmm0
    movdqu [r9+16], xmm0
    movdqu [r9+32], xmm0
    movdqu [r9+48], xmm0
    pop r8
    
    mov byte [r9], 30             ; IORING_OP_SPLICE
    mov eax, [slot_proxy_pipe_w + r8*4]
    mov dword [r9 + 4], eax       ; fd_out = pipe_w
    mov qword [r9 + 8], -1        ; offset_out = -1
    mov qword [r9 + 16], -1       ; offset_in = -1
    mov dword [r9 + 24], r15d     ; len = Content-Length remaining
    mov dword [r9 + 28], 0        ; splice_flags = 0
    mov eax, [slot_proxy_fds + r8*4]
    mov dword [r9 + 44], eax      ; fd_in = proxy Socket
    
    ; user_data = 0x70000 + slot (type 7 = PROXY SPLICE IN)
    mov eax, r8d
    add eax, 0x70000
    mov qword [r9 + 32], rax
    
    push r8
    mov rcx, [sq_ring]
    mov ebx, [uring_params + 44]
    inc edx
    mov [rcx + rbx], edx
    pop r8
    ret

; --- Subroutine: Submit PROXY SPLICE OUT SQE (Pipe_R -> Client) ---
; Input: r8d = slot index, r15 = bytes to splice
uring_submit_proxy_splice_out_sqe:
    push r8
    mov rcx, [sq_ring]
    mov ebx, [uring_params + 44]
    mov edx, [rcx + rbx]          ; SQ tail
    mov r8d, edx
    mov ebx, [uring_params + 48]
    and r8d, [rcx + rbx]          ; mask
    mov ebx, [uring_params + 64]
    lea rbx, [rcx + rbx]
    mov [rbx + r8 * 4], r8d       ; SQ array entry
    mov r9, [sqes]
    mov r10d, r8d
    shl r10, 6
    add r9, r10                    ; r9 = SQE pointer
    pxor xmm0, xmm0
    movdqu [r9], xmm0
    movdqu [r9+16], xmm0
    movdqu [r9+32], xmm0
    movdqu [r9+48], xmm0
    pop r8
    
    mov byte [r9], 30             ; IORING_OP_SPLICE
    mov eax, [slot_fds + r8*4]
    mov dword [r9 + 4], eax       ; fd_out = Client Socket
    mov qword [r9 + 8], -1        ; offset_out = -1
    mov qword [r9 + 16], -1       ; offset_in = -1
    mov dword [r9 + 24], r15d     ; len = exact bytes from pipe
    mov dword [r9 + 28], 0        ; splice_flags = 0
    mov eax, [slot_proxy_pipe_r + r8*4]
    mov dword [r9 + 44], eax      ; fd_in = pipe_r
    
    ; user_data = 0x80000 + slot (type 8 = PROXY SPLICE OUT)
    mov eax, r8d
    add eax, 0x80000
    mov qword [r9 + 32], rax
    
    push r8
    mov rcx, [sq_ring]
    mov ebx, [uring_params + 44]
    inc edx
    mov [rcx + rbx], edx
    pop r8
    ret

; --- Subroutine: Submit SEND SQE (async send via io_uring) ---
; Input: rsi = buffer ptr, edx = buffer length, r13 = client fd
; Uses cur_slot for user_data tagging
uring_submit_send_sqe:
    push r8
    push rdx
    push rsi
    mov rcx, [sq_ring]
    mov ebx, [uring_params + 44]
    mov edx, [rcx + rbx]          ; SQ tail
    mov r8d, edx
    mov ebx, [uring_params + 48]
    and r8d, [rcx + rbx]          ; mask
    mov ebx, [uring_params + 64]
    lea rbx, [rcx + rbx]
    mov [rbx + r8 * 4], r8d       ; SQ array entry
    mov r9, [sqes]
    mov r10d, r8d
    shl r10, 6
    add r9, r10                    ; r9 = SQE pointer
    ; Zero the SQE
    pxor xmm0, xmm0
    movdqu [r9], xmm0
    movdqu [r9+16], xmm0
    movdqu [r9+32], xmm0
    movdqu [r9+48], xmm0
    ; Dynamic ZC Threshold: ZC is viable ONLY between 16KB and 64KB
    cmp byte [zc_enabled], 1
    jne .zc_disable
    mov eax, [rsp + 8]             ; Load length (pushed rdx)
    cmp eax, 16384                 ; Threshold 16 KB (16384 bytes)
    jl .zc_disable                 ; If < 16KB, DMA is too slow, use CPU copy
    cmp eax, 65535                 ; Threshold 64 KB (TCP TSO max size)
    jg .zc_disable                 ; If > 64KB, hardware DMA pinning fails, use CPU chunking
    mov byte [r9], 39              ; IORING_OP_SEND_ZC (Bare-metal NIC DMA)
    jmp .zc_done
.zc_disable:
    mov byte [r9], 26              ; IORING_OP_SEND (Legacy copy)
.zc_done:
    mov dword [r9 + 4], r13d      ; fd = client socket
    pop rsi                        ; restore buffer ptr
    mov qword [r9 + 16], rsi      ; addr = buffer
    pop rdx                        ; restore length
    mov dword [r9 + 24], edx      ; len
    mov dword [r9 + 28], 0x4000   ; send_flags = MSG_NOSIGNAL
    ; user_data = 0x20000 + slot_idx (type 2 = SEND)
    mov eax, [cur_slot]
    add eax, 0x20000
    mov qword [r9 + 32], rax
    ; Advance SQ tail
    mov rcx, [sq_ring]
    mov ebx, [uring_params + 44]
    mov edx, [rcx + rbx]
    inc edx
    mov [rcx + rbx], edx
    pop r8
    ret

uring_setup:
    ; Zero-init uring_params
    mov rdi, uring_params
    mov rcx, 15
    xor rax, rax
    rep stosq
    mov byte [sqpoll_active], 0

    ; Set flags: IORING_SETUP_SINGLE_ISSUER (4096) | IORING_SETUP_DEFER_TASKRUN (8192) | IORING_SETUP_COOP_TASKRUN (256)
    mov dword [uring_params + 8], 12544

    ; Standard io_uring setup (SQPOLL disabled: adds latency in sync model)
    mov rax, 425
    mov rdi, 256           ; SQ ring entries
    mov rsi, uring_params
    syscall
    cmp eax, 0
    jl accept_loop

.setup_rings:
    mov [uring_fd], eax

    push r12
    mov rax, 1
    mov rdi, 1
    mov rsi, msg_uring_ok
    mov rdx, msg_uring_ok_len
    syscall
    ; Log SQPOLL status
    cmp byte [sqpoll_active], 1
    jne .skip_sqpoll_log
    mov rax, 1
    mov rdi, 1
    mov rsi, msg_sqpoll_ok
    mov rdx, msg_sqpoll_ok_len
    syscall
.skip_sqpoll_log:
    pop r12

    ; mmap SQ Ring
    mov rax, 9
    mov rdi, 0
    mov rsi, 16384
    mov rdx, 3
    mov r10, 0x8001
    mov r8d, [uring_fd]
    mov r9, 0
    syscall
    mov [sq_ring], rax

    ; mmap CQ Ring
    mov rax, 9
    mov rdi, 0
    mov rsi, 16384
    mov rdx, 3
    mov r10, 0x8001
    mov r8d, [uring_fd]
    mov r9, 0x8000000
    syscall
    mov [cq_ring], rax

    ; mmap SQEs
    mov rax, 9
    mov rdi, 0
    mov rsi, 16384
    mov rdx, 3
    mov r10, 0x8001
    mov r8d, [uring_fd]
    mov r9, 0x10000000
    syscall
    mov [sqes], rax

    mov dword [client_addr_len], 16

    ; === Allocate connection pool: 65536 slots × 4096 = 256MB ===
    mov rax, 9              ; mmap
    xor rdi, rdi
    mov rsi, 65536 * 4096    ; 256MB
    mov rdx, 3              ; PROT_READ | PROT_WRITE
    mov r10, 0x22           ; MAP_PRIVATE | MAP_ANONYMOUS
    mov r8, -1
    xor r9, r9
    syscall
    mov [conn_pool], rax

    ; Init slot free stack (all 65535 slots free)
    xor ecx, ecx
.init_slots:
    mov [slot_free + rcx*4], ecx
    inc ecx
    cmp ecx, 65535
    jl .init_slots
    mov dword [slot_top], 65535
    mov dword [cur_slot], 65535

    ; === REGISTERED BUFFERS: Register conn_pool slots in kernel ===
    ; Build iovec array: 64 entries × {ptr, len=4096}
    xor ecx, ecx
    lea rdi, [reg_iov_array]
    mov rax, [conn_pool]
.build_iov:
    mov [rdi], rax              ; iov_base = conn_pool + slot*4096
    mov qword [rdi + 8], 4096   ; iov_len = 4096
    add rax, 4096
    add rdi, 16
    inc ecx
    cmp ecx, 256
    jl .build_iov

    ; io_uring_register(fd, IORING_REGISTER_BUFFERS=0, iov_array, 256)
    mov rax, 427                ; __NR_io_uring_register
    mov edi, [uring_fd]
    xor esi, esi                ; opcode = IORING_REGISTER_BUFFERS (0)
    lea rdx, [reg_iov_array]
    mov r10, 256                 ; nr_bufs
    syscall
    cmp eax, 0
    jl .skip_regbuf_log
    ; Log registered buffers success
    push r12
    mov rax, 1
    mov rdi, 1
    mov rsi, msg_regbuf_ok
    mov rdx, msg_regbuf_ok_len
    syscall
    pop r12
.skip_regbuf_log:

    ; === FIXED FILE REGISTRATION ===
    ; Register ALL listening socket fds for zero fget/fput overhead
    xor ecx, ecx
    mov ebx, [listen_count]
.reg_ff_loop:
    cmp ecx, ebx
    jge .reg_ff_done
    mov r12d, [listen_fds + rcx*4]
    mov [fixed_fds + rcx*4], r12d
    inc ecx
    jmp .reg_ff_loop
.reg_ff_done:
    mov dword [fixed_fds + rbx*4], -1   ; sentinel
    
    mov rax, 427                     ; __NR_io_uring_register
    mov edi, [uring_fd]
    mov esi, 2                       ; IORING_REGISTER_FILES
    lea rdx, [fixed_fds]
    mov r10, rbx                     ; nr_fds = listen_count
    syscall
    cmp eax, 0
    jl .skip_fixedfiles_log
    push r12
    mov rax, 1
    mov rdi, 1
    mov rsi, msg_fixedfiles_ok
    mov rdx, msg_fixedfiles_ok_len
    syscall
    pop r12
.skip_fixedfiles_log:

    ; Multi-shot Accept: submit ONE accept SQE per listening socket
    xor r15d, r15d
.accept_sqe_loop:
    cmp r15d, dword [listen_count]
    jge .accept_sqe_done
    
    mov r12d, [listen_fds + r15*4]
    
    ; TCP_NODELAY for uring path
    mov rax, 54
    mov rdi, r12
    mov rsi, 6      ; SOL_TCP
    mov rdx, 1      ; TCP_NODELAY
    mov r10, optval
    mov r8, 4
    syscall
    
    call uring_submit_one_accept
    
    inc r15d
    jmp .accept_sqe_loop
    
.accept_sqe_done:

    ; Kickstart: flush ALL the initial SQEs to kernel
    mov rax, 426                ; io_uring_enter
    mov edi, [uring_fd]
    mov esi, [listen_count]     ; to_submit = listen_count
    mov rdx, 0                  ; min_complete = 0
    mov r10, 0                  ; flags = 0
    mov r8, 0
    mov r9, 0
    syscall

    ; Multi-shot log accepted
    push r12
    mov rax, 1
    mov rdi, 1
    mov rsi, msg_multishot_ok
    mov rdx, msg_multishot_ok_len
    syscall
    
    pop r12

    ; ==============================================================
    ; TLS HANDSHAKE PIPELINE SETUP (per-worker)
    ; Add IORING_OP_READ to tls_res_fd[0] to accept handshaked TLS clients
    ; ==============================================================
    cmp byte [tls_enabled], 1
    jne .skip_tls_res_poll
    
    mov r9, [sqes]
    mov rcx, [sq_ring]
    mov ebx, [uring_params + 44] ; sq_tail offset
    mov edx, [rcx + rbx]         ; tail
    mov r8d, edx
    mov ebx, [uring_params + 48] ; sq_mask offset
    and r8d, [rcx + rbx]         ; (tail & mask)
    mov ebx, [uring_params + 64] ; sq_array offset
    lea rbx, [rcx + rbx]
    mov [rbx + r8 * 4], r8d      ; write index to array
    mov r10d, r8d
    shl r10, 6
    add r9, r10                  ; sqe block pointer
    pxor xmm0, xmm0
    movdqu [r9], xmm0
    movdqu [r9+16], xmm0
    movdqu [r9+32], xmm0
    movdqu [r9+48], xmm0
    
    mov byte [r9], 22           ; IORING_OP_READ
    mov edi, [tls_res_fd]       ; tls_res_fd[0] (read end)
    mov dword [r9 + 4], edi     
    mov qword [r9 + 8], -1      ; offset = -1 (pipe stream)
    mov rax, handshake_out_buf
    mov qword [r9 + 16], rax    ; addr
    mov dword [r9 + 24], 4108   ; len = Header(12) + Data(4096)
    
    ; user_data = TYPE_TLS_REPLY (Type 11: 0xB0000)
    mov rax, 0xB0000
    mov qword [r9 + 32], rax
    
    mov ebx, [uring_params + 44]
    inc edx
    mov [rcx + rbx], edx
.skip_tls_res_poll:

    ; ==============================================================
    ; PROXY CONNECTION POOL INIT (per-worker, after fork)
    ; Scan vhosts for first proxy route, sockaddr cache, pre-connect.
    ; ==============================================================

    ; Initialize proxy_pool_tops to 0 for all 256 routes
    push rdi
    push rcx
    lea rdi, [proxy_pool_tops]
    xor eax, eax
    mov rcx, 256
    rep stosd
    pop rcx
    pop rdi

    ; Find first proxy location: scan vhosts[0..N].locs[0..M]
    xor ecx, ecx                       ; vhost index
.pool_scan_vhosts:
    cmp ecx, 16                        ; max vhosts
    jge .pool_init_done
    mov eax, ecx
    imul eax, 2048
    lea r12, [vhosts + rax]
    movzx edi, word [r12 + 318]        ; loc_count
    test edi, edi
    jz .pool_next_vhost

    xor edx, edx                       ; location index
.pool_scan_locs:
    cmp edx, edi
    jge .pool_next_vhost
    push rcx
    push rdx
    push rdi
    imul eax, edx, 144
    lea r11, [r12 + 320 + rax]         ; r11 = &locs[i]
    movzx eax, word [r11 + 140]        ; is_proxy flag
    test eax, eax
    jz .pool_next_loc

    ; Found a proxy route! Structurally copy sockaddr blob into proxy_pool_addr
    lea rdi, [proxy_pool_addr]
    lea rsi, [r11 + 32]

    push rcx
    mov rcx, 14
    rep movsq         ; copy 112 bytes
    pop rcx

    lea rsi, [proxy_pool_addr]
    movzx rax, word [rsi]      ; Load AF_UNIX (1) or AF_INET (2) family
    cmp rax, 2
    je .pool_inet_len

.pool_unix_len:
    ; AF_UNIX: calculate strlen of path
    lea rdi, [rsi + 2]
    push rcx
    xor ecx, ecx
.pool_copy_path:
    mov al, [rdi + rcx]
    cmp al, 0
    je .pool_path_done
    inc ecx
    jmp .pool_copy_path
.pool_path_done:
    add ecx, 3
    mov [proxy_pool_addrlen], ecx
    pop rcx
    jmp .pool_len_done

.pool_inet_len:
    ; AF_INET: fixed length 16
    mov dword [proxy_pool_addrlen], 16

.pool_len_done:
    ; Compute id_route = (ecx * 16) + edx
    ; rcx is vhost_id, rdx is loc_id
    push rax
    mov rax, rcx
    shl rax, 4
    add rax, rdx
    mov r14, rax              ; r14 = id_route (0..255)
    pop rax
    
    ; ------------- GLOBAL WARM POOL INITIALIZER -------------
    ; We aggressively PRE-CONNECT proxy_pool_size_global connections
    ; for BOTH AF_INET and AF_UNIX to bypass synchronous latency.
    mov r13d, [proxy_pool_size_global]

.pool_warm_loop:
    test r13d, r13d
    jz .pool_warm_skip
    
    ; Create & connect TCP socket instantly
    call proxy_pool_create_one
    cmp eax, 0
    jl .pool_warm_fail
    
    ; Push ready FD into the stack array for this id_route
    ; Dest: proxy_pool_stacks[id_route][top]
    ; eax is FD
    push r11
    push rdi
    mov r11d, dword [proxy_pool_tops + r14*4]
    
    ; Addr = proxy_pool_stacks + (r14 * 256 * 4) + (r11 * 4)
    ; r14*1024
    push rdx
    mov rdi, r14
    shl rdi, 10
    lea rdx, [proxy_pool_stacks + rdi]
    ; add r11 * 4
    mov rdi, r11
    shl rdi, 2
    add rdx, rdi
    mov [rdx], eax
    pop rdx
    
    ; Increment top
    inc r11d
    mov dword [proxy_pool_tops + r14*4], r11d
    
    pop rdi
    pop r11

    dec r13d
    jmp .pool_warm_loop

.pool_warm_fail:
    ; A connection failed to warm up (e.g., backend down).
    ; We tolerate it gracefully.

.pool_warm_skip:
    ; -------------------------------------------------------------------

    ; Go to next location! Do NOT jump to .pool_init_done
    jmp .pool_next_loc

.pool_next_loc:
    pop rdi
    pop rdx
    pop rcx
    inc edx
    jmp .pool_scan_locs

.pool_next_vhost:
    inc ecx
    jmp .pool_scan_vhosts

.pool_init_done:
    ; Log success for ALL proxy pools
    mov rax, 1
    mov rdi, 1
    mov rsi, msg_pool_ok
    mov rdx, msg_pool_ok_len
    syscall

    jmp uring_event_loop

; ==============================================================================
; Subroutine: Write access log to log_fd via io_uring
; Inputs: r15 = buffer address, rdx = length
; Uses cur_slot for user_data
; ==============================================================================
submit_access_log_async:
    cmp byte [access_log_enabled], 1
    jne .log_done
    
    cmp byte [uring_enabled], 1
    je .uring_log
    
    ; Legacy synchronous fallback
    push rax
    push rdi
    push rsi
    push rdx
    mov rax, 1           ; sys_write
    mov edi, [log_fd]
    mov rsi, r15
    ; rdx already contains length
    syscall
    pop rdx
    pop rsi
    pop rdi
    pop rax
    jmp .log_done
    
.uring_log:
    
    ; Setup IORING_OP_WRITE (opcode 26)
    push r8
    mov rcx, [sq_ring]
    mov r8d, [uring_params + 44]  ; sq_tail_off is 44!
    mov eax, [rcx + r8]           ; copy sq_tail
    mov ebx, [uring_params + 48]  ; sq_mask_off
    and eax, [rcx + rbx]          ; fetch mask from sq_ring + sq_mask_off
    shl rax, 6
    mov r9, [sqes]
    add r9, rax                   ; r9 = sqe
    
    ; zero out sqe
    pxor xmm0, xmm0
    movdqu [r9], xmm0
    movdqu [r9+16], xmm0
    movdqu [r9+32], xmm0
    movdqu [r9+48], xmm0
    
    mov byte [r9], 26             ; IORING_OP_WRITE
    mov eax, [log_fd]
    mov dword [r9 + 4], eax
    mov qword [r9 + 8], -1        ; offset = 0xFFFFFFFFFFFFFFFF (APPEND)
    mov qword [r9 + 16], r15      ; point
    mov dword [r9 + 24], edx      ; len
    
    ; user_data = 0xA0000 + cur_slot (type 10 = LOG_WRITE)
    mov eax, [cur_slot]
    add eax, 0xA0000
    mov qword [r9 + 32], rax
    
    ; Advance SQ tail
    mov eax, [rcx + r8]           ; reload unmasked sq_tail
    inc eax
    mov [rcx + r8], eax           ; store back to sq_tail
    pop r8
.log_done:
    ret

uring_event_loop:
    mov dword [cqe_batch_count], 0   ; reset EQC batch counter
    ; In SQPOLL mode, submissions are handled by the kernel thread
    ; We only need io_uring_enter for waiting on completions
    cmp byte [sqpoll_active], 1
    jne .uring_enter_normal

    ; SQPOLL: kernel thread handles submissions, just wait for CQEs
    ; Also wake the SQ thread if it's sleeping
    mov rax, 426
    mov edi, [uring_fd]
    mov rsi, 0                     ; to_submit = 0 (SQPOLL handles this)
    mov rdx, 1                     ; min_complete = 1
    mov r10, 5                     ; IORING_ENTER_GETEVENTS(1) | SQ_WAKEUP(4)
    mov r8, 0
    mov r9, 0
    syscall
    jmp .uring_dispatch

.uring_enter_normal:
    ; Calculate pending SQEs to submit
    ; pending = SQ tail (local) - SQ head (kernel)
    mov rcx, [sq_ring]
    mov ebx, [uring_params + 44]   ; sq_tail_off
    mov esi, [rcx + rbx]           ; SQ tail (our writes)
    mov ebx, [uring_params + 40]   ; sq_head_off
    sub esi, [rcx + rbx]           ; pending = tail - head (kernel consumed)
    ; esi = number of pending SQEs to submit (could be 0)
    
    ; Standard mode: flush pending SQEs + wait for 1 CQE
    mov rax, 426
    mov edi, [uring_fd]
    ; rsi already = pending count
    mov rdx, 1
    mov r10, 1                     ; IORING_ENTER_GETEVENTS
    mov r8, 0
    mov r9, 0
    syscall
    
    ; If io_uring_enter failed, yield CPU to avoid spinning
    cmp rax, 0
    jl .uring_yield
    jmp .uring_dispatch

.uring_yield:
    ; sched_yield() to prevent 100% CPU on transient errors
    mov rax, 24                    ; sys_sched_yield
    syscall
    jmp uring_event_loop

.uring_dispatch:
    mov rcx, [cq_ring]
    mov ebx, [uring_params + 80]
    mov r8d, [rcx + rbx]

uring_cqe_continue:
    ; --- SQ RING OVERFLOW GUARD ---
    ; Limit CQEs per batch: 80 CQEs * 3 max SQEs/CQE = 240 < 256 ring entries
    inc dword [cqe_batch_count]
    cmp dword [cqe_batch_count], 80
    jge uring_event_loop              ; flush pending SQEs before overflow
    
    ; --- SAFELY FETCH CQ HEAD EVERY LOOP CYCLE ---
    mov rcx, [cq_ring]
    mov ebx, [uring_params + 80]
    mov r8d, [rcx + rbx]

    ; Fetch CQ Tail
    mov ebx, [uring_params + 84]
    mov r15d, [rcx + rbx]

    cmp r8d, r15d
    je uring_event_loop

    ; Get CQE
    mov r9d, r8d
    mov ebx, [uring_params + 88]
    and r9d, [rcx + rbx]
    mov r10, rcx
    mov ebx, [uring_params + 100]
    add r10, rbx
    shl r9, 4
    add r10, r9

    mov r14, [r10]                ; user_data
    mov eax, [r10 + 8]           ; res

    ; Advance QC head
    inc r8d
    mov rcx, [cq_ring]
    mov ebx, [uring_params + 80]
    mov [rcx + rbx], r8d

    ; === Dispatch ===
    ; Ignore zero-copy CQEs notifications
    mov ebx, [r10 + 12]
    test ebx, 8                  ; IORING_CQE_F_NOTIF
    jnz skip_cqe

    ; --- Type-based dispatch: type = user_data >> 16, slot = user_data & 0xFFFF ---
    mov ecx, r14d
    shr ecx, 16
    cmp ecx, 1
    je handle_keepalive_read
    cmp ecx, 2
    je handle_send_complete
    cmp ecx, 3
    je handle_proxy_read_cqe
    cmp ecx, 4
    je handle_poll_complete
    cmp ecx, 5
    je handle_proxy_connect_cqe
    cmp ecx, 6
    je handle_proxy_send_cqe
    cmp ecx, 7
    je handle_proxy_splice_in_cqe
    cmp ecx, 8
    je handle_proxy_splice_out_cqe
    cmp ecx, 9
    je handle_proxy_poll_cqe
    cmp ecx, 10
    je skip_cqe    ; LOG_WRITE completion
    cmp ecx, 11
    je handle_tls_reply
    cmp ecx, 12
    je handle_accept

    jmp skip_cqe

handle_tls_reply:
    ; eax = bytes read
    cmp eax, 12
    jl skip_cqe    ; Ignore incomplete TLS pipe reads
    
    ; Re-submit the pipe READ to catch the next client
    push r10
    push r8
    push rax
    
    mov r9, [sqes]
    mov rcx, [sq_ring]
    mov ebx, [uring_params + 44]
    mov edx, [rcx + rbx]
    mov r8d, edx
    mov ebx, [uring_params + 48]
    and r8d, [rcx + rbx]
    mov ebx, [uring_params + 64]
    lea rbx, [rcx + rbx]
    mov [rbx + r8 * 4], r8d
    mov r10d, r8d
    shl r10, 6
    add r9, r10
    pxor xmm0, xmm0
    movdqu [r9], xmm0
    movdqu [r9+16], xmm0
    movdqu [r9+32], xmm0
    movdqu [r9+48], xmm0
    
    mov byte [r9], 22           ; IORING_OP_READ
    mov edi, [tls_res_fd]
    mov dword [r9 + 4], edi     
    mov qword [r9 + 8], -1
    mov rax, handshake_out_buf
    mov qword [r9 + 16], rax
    mov dword [r9 + 24], 4108   ; Read Header(12) + Data(4096)
    
    mov rax, 0xB0000
    mov qword [r9 + 32], rax
    
    mov ebx, [uring_params + 44]
    inc edx
    mov [rcx + rbx], edx
    
    pop rax
    pop r8
    pop r10
 
    ; Extract handshaked fd, port AND data_len!
    mov r13d, [handshake_out_buf]
    mov r14d, [handshake_out_buf + 4]
    mov r11d, [handshake_out_buf + 8]  ; r11d = data_len
    
    mov [cqe_saved_head], r8d
    mov [cqe_saved_tail], r15d
    
    ; Assign slot
    mov eax, [slot_top]
    test eax, eax
    jz .tls_no_slot_fallback
    dec eax
    mov [slot_top], eax
    mov eax, dword [slot_free + rax*4]
    mov [cur_slot], eax
    mov r8d, eax
    mov [slot_listen_fds + r8*4], r14d   ; RESTORE PORT MAPPING FOR VHOST MATCHING!
    mov [slot_fds + rax*4], r13d
    
    ; --- RESTORED: TLS 1.3 PRE-BUFFER HANDOFF ---
    test r11d, r11d
    jz .submit_tls_read

    ; Safety check: do we have the full data promised by data_len?
    lea r9d, [r11d + 12]
    cmp eax, r9d
    jl .submit_tls_read              ; If incomplete, fallback to standard read logic

    ; Pre-buffered decrypted data found! (Managed handoff for TLS 1.3 desync)
    mov rax, r8                     ; cur_slot
    shl rax, 12                     ; 4096 bytes per slot
    mov rdi, [conn_pool]
    test rdi, rdi
    jz .submit_tls_read              ; Safety check!
    add rdi, rax                    ; rdi = destination
    
    push rdi                        ; Save start of buffer
    lea rsi, [handshake_out_buf + 12] ; source data
    mov ecx, r11d                   ; length
    cld                             ; Clear direction flag for rep movsb!
    rep movsb                       ; Copy decrypted request to slot!
    pop rdi                         ; Restore start of buffer
    
    ; Prepare pipeline constraints
    mov r9, rdi
    add r9, r11                     ; end = start + data_len
    mov [slot_pipeline_end_buf + r8*8], r9
    mov [slot_pipeline_next_req + r8*8], r9
    
    mov rsi, rdi                    ; rsi = start of request for parser
    jmp read_request_parse_buffer_loop

.submit_tls_read:
    mov r8d, dword [cur_slot]
    call uring_submit_read_sqe
    mov r8d, [cqe_saved_head]
    mov r15d, [cqe_saved_tail]
    jmp uring_cqe_continue

.tls_no_slot_fallback:
    mov rax, 1                     ; sys_write
    mov rdi, r13
    mov rsi, msg_503
    mov rdx, msg_503_len
    syscall
    mov rax, 3                     ; sys_close
    mov rdi, r13
    syscall
    mov r8d, [cqe_saved_head]
    mov r15d, [cqe_saved_tail]
    jmp uring_cqe_continue

skip_cqe:
    jmp uring_cqe_continue

handle_proxy_splice_in_cqe:
    ; Data moved from proxy to pipe!
    and r14d, 0xFFFF
    mov r8d, r14d
    cmp byte [slot_proxy_state + r8], 0
    je proxy_stale_cqe
    
    ; If eax < 0, error!
    cmp eax, 0
    jl proxy_emit_502
    
    ; We don't really care about IN, since SPLICE_OUT handles the finality!
    jmp uring_cqe_continue

handle_proxy_splice_out_cqe:
    ; Proxy Payload was fully transmitted from the Kernel Pipe to the Client!
    and r14d, 0xFFFF
    mov r8d, r14d
    mov [cur_slot], r8d
    
    cmp byte [slot_proxy_state + r8], 0
    je proxy_stale_cqe
    
    cmp eax, 0
    jle close_conn  ; If pipe->client fails, close everything
    
    ; SPLICE_OUT completed. The proxy socket was perfectly chunked via MSG_PEEK calculation!
    ; We MUST recycle the backend socket to Keep-Alive!
    mov r14d, [slot_proxy_fds + r8*4]
    push r8
    mov edi, r14d
    call proxy_pool_release
    pop r8
    mov dword [slot_proxy_fds + r8*4], 0
    
    ; Reset keeping
    mov dword [slot_proxy_resp_total + r8*4], 0
    mov dword [slot_proxy_resp_received + r8*4], 0
    mov byte [slot_proxy_state + r8], 0
    
    mov [cqe_saved_head], r8d
    mov [cqe_saved_tail], r15d
    
    ; Pipeline handle next request
    jmp send_done_keepalive

proxy_stale_cqe:
    ; CLOSE CQE (0xDEAD), unknown, or stale proxy CQE → skip
    jmp uring_cqe_continue

handle_proxy_connect_cqe:
    ; The proxy socket is officially Connected asynchronously (Non-Blocking)
    ; eax contains the return code (0 = OK)
    and r14d, 0xFFFF
    mov r8d, r14d          ; r8d = slot
    
    ; Guard: ignore stale CQE if proxy already closed
    cmp byte [slot_proxy_state + r8], 0
    je proxy_stale_cqe
    
    cmp eax, 0
    jl proxy_emit_502     ; 502 Bad Gateway if UNIX Connect failed!
    
    ; Retrieve the TRUE Pointer from the Client Request
    mov rsi, [slot_proxy_req_ptr + r8*8]
    
    ; The exact length was calculated before the async gap:
    mov edx, [slot_proxy_req_len + r8*4]
    
    mov r14d, [slot_proxy_fds + r8*4] ; fd proxy
    
    call uring_submit_proxy_send_sqe
    mov r8d, [cqe_saved_head]
    mov r15d, [cqe_saved_tail]
    jmp uring_cqe_continue

proxy_emit_502:
    ; Convert EAX (negative errno) to positive EAX for hex dumping
    neg eax
    mov ecx, eax
    
    ; Convert 1-byte error to 2 hex characters! (Error is likely 2 (ENOENT), 13 (EACCES) or 111 (ECONNREFUSED))
    mov edi, ecx
    and edi, 0xF
    cmp edi, 9
    jbe .is_digit_low
    add edi, 7
.is_digit_low:
    add edi, '0'
    mov byte [msg_502 + 76], dil ; msg_502+76 is the last byte of body
    
    mov edi, ecx
    shr edi, 4
    and edi, 0xF
    cmp edi, 9
    jbe .is_digit_hi
    add edi, 7
.is_digit_hi:
    add edi, '0'
    mov byte [msg_502 + 75], dil
    
    ; Proxy FD and pipes are already closed by .proxy_err_st1 caller
    ; Just reset the proxy_fd tracker in case it wasn't zeroed
    mov dword [slot_proxy_fds + r8*4], 0
    mov byte [slot_proxy_state + r8], 0
    
    ; Send 502 tracking message using sys_write to client
    mov r13d, [slot_fds + r8*4]
    mov rax, 1
    mov rdi, r13
    lea rsi, [msg_502]
    mov rdx, msg_502_len
    syscall

    ; Free slot back to free-stack
    mov eax, [slot_top]
    mov [slot_free + rax*4], r8d
    inc dword [slot_top]

    ; Close the client socket via close_conn (which handles io_uring close)
    mov [cur_slot], r8d
    mov dword [cur_slot], 65535    ; prevent close_conn from double-freeing slot
    
    ; Close client socket
    mov rax, 3
    mov rdi, r13
    syscall
    mov dword [slot_fds + r8*4], 0
    
    jmp uring_cqe_continue

handle_proxy_send_cqe:
    and r14d, 0xFFFF
    mov r8d, r14d
    
    ; Guard: ignore stale CQE if proxy already closed
    cmp byte [slot_proxy_state + r8], 0
    je proxy_stale_cqe
    
    ; === Zéro-Copy / SEND Kernel Support Guard ===
    cmp eax, 0
    jl proxy_emit_502
    
    
    ; We submit an asynchronous POLL to pump the response from Node natively without blocking io-wq!
    call uring_submit_proxy_poll_sqe
    mov r8d, [cqe_saved_head]
    mov r15d, [cqe_saved_tail]
    jmp uring_cqe_continue
    
handle_proxy_poll_cqe:
    mov [cqe_saved_head], r8d
    mov [cqe_saved_tail], r15d
    
    ; The socket proxy is READY TO BE READ (Backend has responded!)
    and r14d, 0xFFFF
    mov r8d, r14d          ; r8d = slot index
    
    ; Guard: ignore stale CQE if proxy already closed
    cmp byte [slot_proxy_state + r8], 0
    je proxy_stale_cqe
    
    mov [cur_slot], r8d
    
    ; Submit a buffered READ into conn_pool to analyze the Node.js response
    mov r14d, [slot_proxy_fds + r8*4]
    call uring_submit_proxy_read_sqe
    
    mov r8d, [cqe_saved_head]
    mov r15d, [cqe_saved_tail]
    jmp uring_cqe_continue
    
handle_proxy_read_cqe:
    ; CQE res in eax (bytes read from proxy into conn_pool buffer)
    and r14d, 0xFFFF
    mov r8d, r14d          ; r8d = slot index
    
    ; Guard: ignore stale CQE if proxy already closed
    cmp byte [slot_proxy_state + r8], 0
    je proxy_stale_cqe
    
    mov [cur_slot], r8d
    
    cmp eax, 0
    jle proxy_eof
    
    ; --- BSS TRACKERS UPDATE ---
    mov ecx, [slot_proxy_resp_received + r8*4]
    add ecx, eax
    mov [slot_proxy_resp_received + r8*4], ecx
    mov r12d, eax          ; save bytes read to r12d (callee-saved)
    push r12
    
    ; Check if we already parsed headers
    cmp dword [slot_proxy_resp_total + r8*4], 0
    jne .proxy_read_send_zc
    
    ; === PHASE 2: PARSE CONTENT-LENGTH ===
    mov edi, r8d
    shl edi, 12            ; slot*4096
    mov rsi, [conn_pool]
    add rsi, rdi           ; rsi = ptr to current buffer
    
    mov rcx, rsi
    mov rdx, rsi
    add rdx, r12           ; max bound = buffer + bytes_read! (NOT 4096)

    ; --- AVX2 SIMD SETUP for \r\n\r\n ---
    mov eax, 0x0D0D0D0D
    vmovd xmm1, eax
    vpbroadcastd ymm1, xmm1 ; ymm1 = [ \r, \r, ... ]
    
    mov r10, rdx
    sub r10, 32            ; r10 = safe AVX2 limit (to avoid Page Fault / OOB read)
    cmp rcx, r10
    jae .proxy_find_end_scalar
    
.proxy_find_end_avx2:
    vmovdqu ymm0, [rcx]
    vpcmpeqb ymm2, ymm0, ymm1
    vpmovmskb eax, ymm2
    test eax, eax
    jz .proxy_find_end_avx2_next
    
.proxy_find_end_avx2_tzcnt:
    tzcnt ebx, eax
    ; ebx is index (0-31) of '\r'
    cmp dword [rcx + rbx], 0x0A0D0A0D ; \r\n\r\n
    je .proxy_found_end_avx
    ; clear this bit and try next
    btr eax, ebx
    test eax, eax
    jnz .proxy_find_end_avx2_tzcnt

.proxy_find_end_avx2_next:
    add rcx, 32
    cmp rcx, r10
    jb .proxy_find_end_avx2
    
.proxy_find_end_scalar:
    ; Avoid reading past rdx
    mov rax, rdx
    sub rax, rcx
    cmp rax, 4
    jl .proxy_find_end_not_found

    cmp dword [rcx], 0x0A0D0A0D
    je .proxy_found_end
    inc rcx
    jmp .proxy_find_end_scalar

.proxy_find_end_not_found:
    ; Fallback: \r\n\r\n not found. Close connection after chunk.
    mov eax, [slot_proxy_resp_received + r8*4]
    mov dword [slot_proxy_resp_total + r8*4], eax
    jmp .proxy_read_send_zc

.proxy_found_end_avx:
    add rcx, rbx

.proxy_found_end:
    add rcx, 4             ; start of body payload
    mov r11, rcx
    sub r11, rsi           ; r11 = length of headers (up to body start)
    
    mov rcx, rsi
    mov rdx, rsi
    add rdx, r11           ; only scan for Content-Length within Headers!

    cmp byte [avx2_enabled], 1
    je .proxy_cl_simd_start
    cmp byte [avx512_enabled], 1
    je .proxy_cl_simd_start
    jmp .proxy_find_cl_scalar

.proxy_cl_simd_start:
    ; --- AVX2 SIMD SETUP for Content-Length ---
    mov eax, 0x43434343    ; 'C'
    vmovd xmm1, eax
    vpbroadcastd ymm1, xmm1
    
    mov eax, 0x63636363    ; 'c' (NodeJS uses lowercase headers often)
    vmovd xmm3, eax
    vpbroadcastd ymm3, xmm3
    
    mov r10, rdx
    sub r10, 32      ; safe bound for SIMD
    cmp rcx, r10
    jae .proxy_find_cl_scalar
    
.proxy_find_cl_avx2:
    vmovdqu ymm0, [rcx]
    vpcmpeqb ymm2, ymm0, ymm1   ; Match 'C'
    vpcmpeqb ymm4, ymm0, ymm3   ; Match 'c'
    vpor ymm2, ymm2, ymm4
    
    ; NEW: Add 'T'/'t' for Transfer-Encoding detection in SIMD
    vpbroadcastb ymm4, [rel .t_upper]
    vpcmpeqb ymm5, ymm0, ymm4
    vpor ymm2, ymm2, ymm5
    vpbroadcastb ymm4, [rel .t_lower]
    vpcmpeqb ymm5, ymm0, ymm4
    vpor ymm2, ymm2, ymm5
    
    vpmovmskb eax, ymm2
    test eax, eax
    jnz .proxy_find_cl_avx2_tzcnt

.proxy_find_cl_avx2_tzcnt:
    tzcnt ebx, eax
    
    push rcx
    add rcx, rbx         ; rcx points to 'C' or 'c'
    
    ; --- SECURITY: Boundary Verification ---
    cmp rcx, rsi
    jle .avx2_cl_bound_ok
    cmp byte [rcx-1], 0x0A
    jne .avx2_cl_fail
.avx2_cl_bound_ok:

    ; Ensure enough space in buffer
    mov r14, rdx
    sub r14, rcx
    cmp r14, 16
    jl .avx2_cl_fail

    inc rcx              ; point to 'o'
    ; 'ontent-length: ' = 0x6f 6e 74 65 6e 74 2d 6c 65 6e 67 74 68 3a 20
    mov r9, 0x6C2D746E65746E6F  ; 'have it'
    mov r13, 0x4C2D746E65746E6F ; 'have it'
    mov r14, [rcx]
    
    cmp r14, r9
    je .avx2_cl_p2
    cmp r14, r13
    jne .avx2_cl_fail
    
.avx2_cl_p2:
    cmp dword [rcx+8], 0x74676E65 ; 'engt'
    jne .avx2_cl_fail
    cmp word [rcx+12], 0x3A68     ; 'h:'
    jne .avx2_cl_fail
    
    ; Match found!
    mov al, [rcx+rbx]
    or al, 0x20
    cmp al, 't'
    je .avx2_te_matched

    pop rcx
    add rcx, rbx
    add rcx, 15            ; Dot past 'Content-Length:'
    jmp .proxy_atoi_setup

.avx2_te_matched:
    pop rcx
    add rcx, rbx
    ; Found Transfer-Encoding in SIMD!
    ; SECURITY: Mark for forced close — no keep-alive, prevents response smuggling
    mov dword [slot_proxy_resp_total + r8*4], 0x7FFFFFFF
    mov byte [slot_proxy_te_close + r8], 1    ; Force close after forwarding
    jmp .proxy_read_send_zc

.avx2_cl_fail:
    pop rcx
    btr eax, ebx
    test eax, eax
    jnz .proxy_find_cl_avx2_tzcnt

    add rcx, 32
    cmp rcx, r10
    jb .proxy_find_cl_avx2

.t_lower: db 't'
.t_upper: db 'T'
    
.proxy_find_cl_scalar:
    mov rax, rdx
    sub rax, rcx
    cmp rax, 16
    jl .proxy_cl_not_found     ; Not enough bytes left

    mov al, [rcx]
    cmp al, 'C'
    je .proxy_cl_scalar_check
    cmp al, 'c'
    je .proxy_cl_scalar_check
    cmp al, 'T'
    je .proxy_te_scalar_check
    cmp al, 't'
    je .proxy_te_scalar_check
    inc rcx
    jmp .proxy_find_cl_scalar

.proxy_te_scalar_check:
    ; --- SECURITY: Boundary Verification ---
    cmp rcx, rsi
    jle .proxy_te_bound_ok
    cmp byte [rcx-1], 0x0A
    jne .proxy_find_cl_scalar_resume
.proxy_te_bound_ok:
    inc rcx
    ; 'ransfer-' = 0x2D726566736E6172
    mov r14, [rcx]
    mov r9, 0x2D726566736E6172
    cmp r14, r9
    jne .proxy_find_cl_scalar
    ; 'Encoding' = 0x676E69646F636E45
    mov r14, [rcx+8]
    mov r9, 0x676E69646F636E45 ; 'Encoding'
    mov r13, 0x676E69646F636E65 ; 'encoding'
    cmp r14, r9
    je .te_found
    cmp r14, r13
    jne .proxy_find_cl_scalar
.te_found:
    ; It's Transfer-Encoding! Default it to chunked for now.
    ; SECURITY: Mark for forced close — no keep-alive, prevents response smuggling
    mov dword [slot_proxy_resp_total + r8*4], 0x7FFFFFFF
    mov byte [slot_proxy_te_close + r8], 1    ; Force close after forwarding
    jmp .proxy_read_send_zc

    
.proxy_find_cl_scalar_resume:
    inc rcx
    jmp .proxy_find_cl_scalar

.proxy_cl_scalar_check:
    ; --- SECURITY: Boundary Verification ---
    cmp rcx, rsi
    jle .proxy_scalar_bound_ok
    cmp byte [rcx-1], 0x0A
    jne .proxy_find_cl_scalar_resume
.proxy_scalar_bound_ok:
    inc rcx
    mov r9, 0x6C2D746E65746E6F  ; 'have it'
    mov r13, 0x4C2D746E65746E6F ; 'have it'
    mov r14, [rcx]
    cmp r14, r9
    je .scalar_cl_p2
    cmp r14, r13
    jne .proxy_find_cl_scalar
.scalar_cl_p2:
    cmp dword [rcx+8], 0x74676E65 ; 'engt'
    jne .proxy_find_cl_scalar
    cmp word [rcx+12], 0x3A68     ; 'h:'
    jne .proxy_find_cl_scalar
    
    ; Found!
    add rcx, 14
    jmp .proxy_atoi_setup
    
.proxy_cl_not_found:
    mov ebx, 0
    jmp .proxy_cl_done

.proxy_atoi_setup:
    xor ebx, ebx
.proxy_atoi_trim:
    movzx edi, byte [rcx]
    cmp edi, ' '
    jne .proxy_atoi
    inc rcx
    jmp .proxy_atoi_trim
    
.proxy_atoi:
    movzx edi, byte [rcx]
    cmp edi, '0'
    jb .proxy_cl_done
    cmp edi, '9'
    ja .proxy_cl_done
    sub edi, '0'
    imul ebx, 10
    add ebx, edi
    inc rcx
    jmp .proxy_atoi
    
.proxy_cl_done:
    add ebx, r11d          ; Total response size = headers + body length
    mov dword [slot_proxy_resp_total + r8*4], ebx
    
.proxy_read_send_zc:
    ; === PHASE 3: SEND ZC & KEEP-ALIVE DECISION ===
    pop r12                ; r12 = bytes read in this specific read cycle
    
    mov eax, [slot_proxy_resp_received + r8*4]
    cmp eax, [slot_proxy_resp_total + r8*4]
    jl .proxy_read_incomplete
    
    ; 100% of proxy response is received!
    ; SECURITY: Check if TE:chunked response — if so, close instead of keep-alive (anti-smuggling)
    cmp byte [slot_proxy_te_close + r8], 1
    je .proxy_te_force_close
    
    ; Recycle Node backend connection back to pool
    mov r14d, [slot_proxy_fds + r8*4]
    push r8
    push r12
    mov edi, r14d
    call proxy_pool_release
    pop r12
    pop r8
    mov dword [slot_proxy_fds + r8*4], 0
    
    ; Clear trackers for the next Keep-Alive request on this client
    mov dword [slot_proxy_resp_total + r8*4], 0
    mov dword [slot_proxy_resp_received + r8*4], 0
    
    ; Mark proxy routing END, client socket will resume Keep-Alive!
    mov byte [slot_proxy_state + r8], 0
    jmp .proxy_read_incomplete

.proxy_te_force_close:
    ; TE:chunked response completed — close backend + client to prevent smuggling
    mov byte [slot_proxy_te_close + r8], 0  ; Reset flag
    mov byte [slot_proxy_state + r8], 0
    mov dword [slot_proxy_resp_total + r8*4], 0
    mov dword [slot_proxy_resp_received + r8*4], 0
    
    ; Close backend socket (don't recycle to pool — it may have leftover data)
    mov r14d, [slot_proxy_fds + r8*4]
    cmp r14d, 0
    jle .proxy_te_skip_backend_close
    push r8
    mov rax, 3
    mov rdi, r14
    syscall
    pop r8
.proxy_te_skip_backend_close:
    mov dword [slot_proxy_fds + r8*4], 0
    mov [cur_slot], r8d
    mov r13d, [slot_fds + r8*4]
    jmp close_conn              ; Close client connection cleanly
    
.proxy_read_incomplete:
    ; Initiate SEND_ZC to the Client socket
    mov r13d, [slot_fds + r8*4]
    
    mov eax, r8d
    shl eax, 12
    add rax, [conn_pool]
    mov rsi, rax           ; buffer = conn_pool + slot*4096
    mov edx, r12d          ; len = bytes read in this CQE
    
    ; Prevent mem/file loops inside handle_send_complete
    mov qword [slot_mem_remaining + r8*8], 0
    mov qword [slot_file_remaining + r8*8], 0
    
    ; Submit the ASYNC SEND to io_uring!
    call uring_submit_send_sqe
    
    ; Ensure cqe loop continues
    mov r8d, [cqe_saved_head]
    mov r15d, [cqe_saved_tail]
    jmp uring_cqe_continue

proxy_eof:
    ; Node.js closed the backend socket
    mov r13d, [slot_fds + r8*4]
    mov r14d, [slot_proxy_fds + r8*4]
    ; Convert slot index to FDs
    mov r13d, [slot_fds + r8*4]     ; TCP FD client
    mov r14d, [slot_proxy_fds + r8*4] ; UNIX FD Proxy

    ; DEBUG: Print msg_none_ko ("Worker crash") to know proxy closed
    push rax
    push rdi
    push rsi
    push rdx
    mov rax, 1
    mov rdi, 1
    lea rsi, [msg_proxy_err]
    mov rdx, 22
    syscall
    pop rdx
    pop rsi
    pop rdi
    pop rax
    
    ; Close Proxy Socket
    cmp r14d, 0
    jle .proxy_eof_skip_proxy
    mov rax, 3
    mov rdi, r14
    syscall
.proxy_eof_skip_proxy:

    ; Close Downstream Client Socket to cleanly signal the natural HTTP payload end
    cmp r13d, 0
    jle .proxy_eof_skip_client
    mov rax, 3
    mov rdi, r13
    syscall
.proxy_eof_skip_client:

    ; Reset slot state
    mov dword [slot_proxy_fds + r8*4], 0
    mov dword [slot_fds + r8*4], 0
    mov byte [slot_proxy_state + r8], 0
    mov byte [slot_proxy_te_close + r8], 0  ; Clean TE flag on EOF
    
    mov dword [slot_proxy_resp_total + r8*4], 0
    mov dword [slot_proxy_resp_received + r8*4], 0

    ; Free slot back to free-stack
    mov eax, [slot_top]
    mov [slot_free + rax*4], r8d
    inc eax
    mov [slot_top], eax

    cmp byte [uring_enabled], 1
    je .uring_cont
    jmp accept_loop
.uring_cont:
    jmp uring_cqe_continue

handle_accept:
    cmp eax, 0
    jl accept_err

    ; Extract network port from user_data (DO NOT OVERWRITE R8D - IT HOLDS CQ_HEAD)
    mov r9d, r14d
    and r9d, 0xFFFF
    mov r14d, r9d       ; r14d is now purely the network port!

    mov r13d, eax                 ; FD customer
    mov [cqe_saved_head], r8d
    mov [cqe_saved_tail], r15d

    ; Set SO_RCVTIMEO (5s keep-alive timeout)
    mov rax, 54
    mov rdi, r13
    mov rsi, 1              ; SOL_SOCKET
    mov rdx, 20             ; SO_RCVTIMEO
    mov r10, ka_timeout
    mov r8, 16
    syscall

    ; --- TCP_NODELAY (Nagle's Algorithm off) ---
    cmp byte [tcp_nodelay_enabled], 1
    jne .skip_nodelay
    mov rax, 54
    mov rdi, r13
    mov rsi, 6              ; SOL_TCP
    mov rdx, 1              ; TCP_NODELAY
    mov r10, optval
    mov r8, 4
    syscall
.skip_nodelay:

    ; --- TLS 1.3 ASYNC HANDSHAKE (if enabled) ---
    ; O(1) Map Lookup against the Nginx Parser's port_is_ssl array!
    mov r8d, r14d
    movzx r8d, byte [port_is_ssl + r8]
    test r8d, r8d
    jz .skip_tls_handshake
    
    ; Send client_fd (r13d) AND mapping port (r14d) to Handshake Manager via tls_req_fd
    sub rsp, 8
    mov [rsp], r13d
    mov [rsp + 4], r14d
    
    mov rax, 1                  ; sys_write
    mov edi, [tls_req_fd + 4]   ; tls_req_fd[1] is write end
    mov rsi, rsp
    mov rdx, 8
    syscall
    
    add rsp, 8
    
    ; The socket is now owned by the Manager. We drop it from our Event Loop entirely.
    ; When the Manager is done, it will push it back via tls_res_fd and trigger `handle_tls_reply`!
    jmp uring_cqe_continue
.skip_tls_handshake:

    ; Multi-shot: NO need to re-submit accept SQE
    ; The kernel keeps the original SQE active

    ; Allocate slot for this connection
    mov eax, [slot_top]
    test eax, eax
    jz .no_slot_sync_fallback
    dec eax
    mov [slot_top], eax
    mov eax, dword [slot_free + rax*4]
    mov [cur_slot], eax

    ; Store client fd in slot_fds for async SEND completion
    mov [slot_fds + rax*4], r13d

    ; Sync read (1st request on new connection)
    mov rax, 0
    mov rdi, r13
    
    ; Read directly into the slot's conn_pool instead of global buffer!
    mov r8d, dword [cur_slot]
    
    ; --- STRICT PORT-AWARE ROUTING: Bind physical port to Active slot! ---
    mov [slot_listen_fds + r8*4], r14d

    mov eax, r8d
    shl eax, 12
    mov rsi, [conn_pool]
    add rsi, rax
    
    mov rdx, 4096
    mov rax, 0          ; restore rax = 0 for sys_read
    syscall

    cmp rax, -11        ; EAGAIN? (non-blocking socket, data not ready yet)
    je .accept_submit_async_read

    test rax, rax
    jle close_conn

    mov r9, rax
    add r9, rsi
    mov r8d, dword [cur_slot]
    mov [slot_pipeline_end_buf + r8*8], r9
    mov [slot_pipeline_next_req + r8*8], r9

    ; rsi already points to start of slot buffer
    jmp read_request_parse_buffer_loop

.accept_submit_async_read:
    ; Socket is non-blocking and data isn't here yet.
    ; Submit an async io_uring READ and let the event loop handle it.
    mov r8d, [cur_slot]
    call uring_submit_read_sqe
    mov r8d, [cqe_saved_head]
    mov r15d, [cqe_saved_tail]
    jmp uring_cqe_continue

.no_slot_sync_fallback:
    ; No free slots — send 503 Service Unavailable and close immediately.
    ; CRITICAL: Do NOT route through normal_routing with cur_slot=65535
    ; as it would corrupt the slot pool via OOB array access.
    mov rax, 1                     ; sys_write
    mov rdi, r13                   ; customer fd
    mov rsi, msg_503
    mov rdx, msg_503_len
    syscall

    ; Close client socket directly (no slot to free)
    mov rax, 3                     ; sys_close
    mov rdi, r13
    syscall

    mov r8d, [cqe_saved_head]
    mov r15d, [cqe_saved_tail]
    jmp uring_cqe_continue

handle_poll_complete:
    ; POLL_ADD finished (socket is writable!)
    mov ecx, r14d
    and ecx, 0xFFFF               ; slot_idx
    mov [cur_slot], ecx
    mov [cqe_saved_head], r8d
    mov [cqe_saved_tail], r15d
    mov r13d, [slot_fds + rcx*4]  ; client_fd
    
    ; poll_events is in eax. Look for errors (like connection reset)
    cmp eax, 0
    jl close_conn
    ; Safe to resume! Check if it's a proxy splice stream
    mov r8d, ecx
    cmp byte [slot_proxy_state + r8], 1
    je .do_proxy_splice_out
    
    ; Not proxy, resume sendfile!
    jmp do_sendfile

.do_proxy_splice_out:
    mov r15d, [slot_proxy_pipe_len + r8*4]
    call uring_submit_proxy_splice_out_sqe
    mov r8d, [cqe_saved_head]
    mov r15d, [cqe_saved_tail]
    jmp uring_cqe_continue

handle_send_complete:
    ; SEND completed. user_data = 0x200 + slot_idx
    mov ecx, r14d
    and ecx, 0xFFFF               ; slot_idx
    mov [cur_slot], ecx
    mov [cqe_saved_head], r8d
    mov [cqe_saved_tail], r15d
    
    ; Get client fd from slot
    mov r13d, [slot_fds + rcx*4]
    
    ; Check send result
    cmp eax, 0
    jle close_conn                ; error or EOF → close
    
    ; --- PHASE 5: Handle Chunked Memory Send ---
    mov r8d, ecx                  ; r8d = slot_idx
    mov r9, [slot_mem_remaining + r8*8]
    
    cmp r9, 0
    jz .check_sendfile            ; If no memory remained, go straight to sendfile logic

    movsxd r10, eax               ; r10 = bytes actually sent by io_uring
    sub r9, r10                   ; remaining -= bytes_sent
    mov [slot_mem_remaining + r8*8], r9
    
    cmp r9, 0
    jg .continue_mem_send
    
.check_sendfile:
    ; Memory send is completely finished (Headers or Small file).
    ; Are there DISK bytes remaining to send via sys_sendfile?
    mov r12, [slot_file_remaining + r8*8]
    cmp r12, 0
    jg do_sendfile
    
    ; --- FIX: Check if we are in the middle of a proxy multi-chunk ! ---
    cmp byte [slot_proxy_state + ecx], 1
    je .send_done_proxy_resume
    
    ; If nothing left at all (Memory done, Disk done), connection is free for Keep-Alive!
    jmp send_done_keepalive

.send_done_proxy_resume:
    ; The userspace chunk was sent to the client.
    mov r8d, ecx
    
    ; FASTPATH ​​SPLICE: Check if we can route the rest directly inside Kernel!
    ; Re-fetch splice_mode from vhosts config
    mov eax, [slot_proxy_loc_idx + r8*4]
    mov edx, eax
    shr eax, 4              ; eax = vhost index
    and edx, 15             ; edx = location index
    
    imul rax, 2048
    lea r12, [vhosts + rax]
    
    mov eax, 144
    mul edx
    lea r11, [r12 + 320 + rax]
    movzx r13d, word [r11 + 142] ; r13d = splice_mode (1 or 0)
    
    mov r14d, [slot_proxy_fds + r8*4]
    mov ebx, [slot_proxy_resp_total + r8*4]
    mov r15d, ebx
    sub r15d, [slot_proxy_resp_received + r8*4] ; r15d = Exact Bytes remaining
    
    cmp r15d, 0
    jle .proxy_send_done_full
    
    ; Check if SPLICE is enabled for this route!
    cmp r13d, 1
    jne .resume_proxy_userspace_read
    
    ; If we have pipes allocated, we use SPLICE directly!
    cmp dword [slot_proxy_pipe_w + r8*4], 0
    je .resume_proxy_userspace_read
    
    ; --- 100% KERNEL SPLICING ---
    ; 1. Submit SPLICE IN (Proxy -> Pipe)
    call uring_submit_proxy_splice_in_sqe
    
    ; 2. Submit SPLICE OUT (Pipe -> Client)
    call uring_submit_proxy_splice_out_sqe
    
    ; 3. Fake received amount (the Splice CQE will handle the true async callback!)
    mov [slot_proxy_resp_received + r8*4], ebx
    
    mov r8d, [cqe_saved_head]
    mov r15d, [cqe_saved_tail]
    jmp uring_cqe_continue

.resume_proxy_userspace_read:
    ; Fallback: userspace buffered Read
    call uring_submit_proxy_read_sqe
    mov r8d, [cqe_saved_head]
    mov r15d, [cqe_saved_tail]
    jmp uring_cqe_continue

.proxy_send_done_full:
    ; It was completely sent on the first userspace pass!
    jmp send_done_keepalive

.continue_mem_send:
    ; We still have memory to send (Socket Overflow Chunking)
    mov r11, [slot_mem_ptr + r8*8]
    add r11, r10                  ; ptr += bytes_sent
    mov [slot_mem_ptr + r8*8], r11
    
    ; Submit the next chunk (max 32KB)
    mov rsi, r11
    mov rdx, r9
    cmp rdx, 32768
    jle .do_submit_chunk
    mov rdx, 32768
.do_submit_chunk:
    call uring_submit_send_sqe
    mov r8d, [cqe_saved_head]
    mov r15d, [cqe_saved_tail]
    jmp uring_cqe_continue

do_sendfile:
    ; sendfile(out_fd, in_fd, &offset, count)
    mov rax, 40                   ; sys_sendfile (syscall 40)
    mov rdi, r13                  ; out_fd(socket)
    mov rsi, [slot_file_fd + r8*8] ; in_fd (file descriptor)
    lea rdx, [slot_file_offset + r8*8] ; pointer to offset
    mov r10, [slot_file_remaining + r8*8] ; count (total remaining)
    syscall
    
    cmp rax, 0
    jge .sendfile_success
    
.sendfile_error:
    cmp rax, -11                  ; -EAGAIN (Socket Buffer Full)
    je submit_poll_add
    jmp close_conn                ; Fatal Error

.sendfile_success:
    je send_done_keepalive       ; EOF File sent completely
    
    ; Subtract bytes sent from remaining
    mov r12, [slot_file_remaining + r8*8]
    sub r12, rax
    mov [slot_file_remaining + r8*8], r12
    
    cmp r12, 0
    jg do_sendfile               ; Since Non-Blocking, we can loop safely until EAGAIN!
    
send_done_keepalive:
    ; Send succeeded completely → submit READ for next keep-alive request
    mov r8d, [cur_slot]
    call uring_submit_read_sqe
    mov r8d, [cqe_saved_head]
    mov r15d, [cqe_saved_tail]
    jmp uring_cqe_continue

submit_poll_add:
    ; Socket Buffer is full (-EAGAIN). Go to sleep and ask io_uring to wake us!
    mov r8d, [cur_slot]
    call uring_submit_poll_add_sqe
    mov r8d, [cqe_saved_head]
    mov r15d, [cqe_saved_tail]
    jmp uring_cqe_continue

handle_keepalive_read:
    ; user_data = 0x10000 + slot_idx
    and r14d, 0xFFFF
    mov ecx, r14d                 ; slot_idx
    mov [cur_slot], ecx
    mov [cqe_saved_head], r8d
    mov [cqe_saved_tail], r15d

    ; Get client fd from slot
    mov r13d, [slot_fds + rcx*4]

    ; Check read result
    cmp eax, -11                  ; -EAGAIN
    je .retry_read
    cmp eax, 0
    jg .read_ok                   ; EOF or error → drop but log!

    ; --- DEBUG: Read failed. Send 500 with error code ---
    mov r8d, eax
    jmp close_conn
    
.retry_read:
    ; Data not ready yet. Resubmit READ SQE
    mov r8d, ecx
    call uring_submit_read_sqe
    mov r8d, [cqe_saved_head]
    mov r15d, [cqe_saved_tail]
    jmp uring_cqe_continue

.read_ok:
    ; Point analysis to the slot's buffer
    mov ecx, [cur_slot]
    shl ecx, 12                   ; slot*4096
    mov rsi, [conn_pool]
    add rsi, rcx                  ; rsi = slot buffer

    movsxd rax, dword [r10 + 8]   ; re-read res (bytes)
    mov r9, rax
    add r9, rsi                   ; r9 = end of data
    push rax
    mov eax, dword [cur_slot]
    mov [slot_pipeline_end_buf + rax*8], r9
    pop rax

    jmp read_request_parse_buffer_loop

accept_err:
    ; Multishot ACCEPT error. Check if fatal or transient.
    ; -EAGAIN(-11), -ECONNABORTED(-103), -EMFILE(-24): transient → multishot stays active, just skip
    ; -ECANCELED(-125), -EINVAL(-22): fatal → re-arm
    cmp eax, -125              ; -ECANCELED
    je .accept_rearm
    cmp eax, -22               ; -EINVAL
    je .accept_rearm
    ; Transient error: multishot is still active, don't re-submit
    jmp uring_cqe_continue

.accept_rearm:
    mov r12, r14
    and r12, 0xFFF
    call uring_submit_one_accept
    jmp uring_cqe_continue

; === SIGTERM graceful shutdown handler ===
sigterm_handler:
    mov al, 1
    xchg byte [shutdown_flag], al   ; Atomic write (signal-safe, no torn reads)
    mov rax, 231            ; sys_exit_group safely immediately ends the program
    mov rdi, 0
    syscall

; === SIGHUP cache reload handler ===
sighup_handler:
    mov al, 1
    xchg byte [reload_flag], al     ; Atomic write (signal-safe, no torn reads)
    ret

; === Reload cache (called from worker loop) ===
reload_cache:
    push rbp
    mov rbp, rsp
    push rbx
    
    ; Log reload attempt
    mov rax, 1
    mov rdi, 1
    mov rsi, msg_uring_ok ; Just to print something (reusing a string for now)
    ; Actually we can just silently reload for now
    
    ; Reset cache table and pool
    mov rdi, cache_table
    mov rcx, 512
    xor rax, rax
    rep stosq
    
    mov rax, [cache_pool]
    mov [cache_pool_ptr], rax

    ; Scan directory and cache dynamically
    call scan_and_cache_directory
    ; Duplicates "/" entry for index.html
    mov qword [buffer], 0
    mov byte [buffer], '/'
    mov dword [buffer+1], 0x65646E69     ; "India"
    mov dword [buffer+5], 0x74682E78     ; "x.ht"
    mov word [buffer+9], 0x6C6D          ; "ml"
    mov byte [buffer+11], ' '
    xor rax, rax
    crc32 rax, qword [buffer]
    and rax, 0x3FF                       ; FIX: 1024 entries, not 256
    lea rcx, [cache_table]
    mov rdx, rax
    shl rdx, 6                           ; FIX: 64 bytes per entry, not 16
    mov rsi, [rcx + rdx]
    mov r8,  [rcx + rdx + 8]
    test rsi, rsi
    jz .rc_final
    ; Now create the alias entry for "/ " (the root URL)
    mov qword [buffer], 0
    mov word [buffer], 0x202F            ; "/ "
    xor rax, rax
    crc32 rax, qword [buffer]
    and rax, 0x3FF                       ; FIX: 1024 entries
    shl rax, 6                           ; FIX: 64 bytes per entry
    mov [rcx + rax], rsi                 ; response ptr
    mov [rcx + rax + 8], r8              ; response length
    ; Copy ETag, fd, filesize from source entry
    mov r9, [rcx + rdx + 16]
    mov [rcx + rax + 16], r9             ; ETag
    mov r9, [rcx + rdx + 24]
    mov [rcx + rax + 24], r9             ; file fd
    mov r9, [rcx + rdx + 32]
    mov [rcx + rax + 32], r9             ; file size
    ; Store URI key for collision guard
    mov qword [rcx + rax + 40], 0x202F   ; "/ " padded with zeros
.rc_final:
    pop rbx
    pop rbp
    ret

; === Small 8-bit itoa (appends to rdi) ===
_itoa_8:
    push rsi
    push rcx
    mov rcx, 0xCCCCCCCCCCCCCCCD
    lea rsi, [log_buf + 254]
.i8_div:
    mov r9, rax
    mul rcx
    shr rdx, 3
    lea r10, [rdx + rdx*4]
    add r10, r10
    sub r9, r10
    add r9b, '0'
    dec rsi
    mov [rsi], r9b
    mov rax, rdx
    test rax, rax
    jnz .i8_div
.i8_copy:
    mov al, [rsi]
    mov [rdi], al
    inc rdi
    inc rsi
    cmp rsi, log_buf + 254
    jl .i8_copy
    pop rcx
    pop rsi
    ret

; === Dynamic directory scanner ===
scan_and_cache_directory:
    push rbp
    mov rbp, rsp
    push r12
    push r13
    push r14
    push r15
    push rbx
    
    mov ebx, [vhost_count_global]
    test ebx, ebx
    jz .scan_done
    
    xor r12d, r12d      ; i = 0
.vhost_loop:
    cmp r12d, ebx
    jge .scan_done
    
    mov eax, 1024
    mul r12d
    lea r14, [vhosts + rax + 64]   ; r14 = vhosts[i].doc_root
    
    ; length of doc_root -> rcx
    mov rcx, r14
.len_loop:
    cmp byte [rcx], 0
    jz .len_done
    inc rcx
    jmp .len_loop
.len_done:
    sub rcx, r14
    push rcx            ; save doc_root length!

    ; sys_open
    mov rax, 2
    mov rdi, r14
    mov rsi, 65536      ; O_RDONLY|O_DIRECTORY
    mov rdx, 0
    syscall
    cmp rax, 0
    jl .next_vhost_pop
    mov r13, rax        ; dir_fd
    
.scan_loop:
    mov rax, 217        ; sys_getdents64
    mov rdi, r13
    lea rsi, [cache_scan_buf]
    mov rdx, 2048
    syscall
    cmp rax, 0
    jle .close_dir
    
    mov r15, rax        ; bytes read
    lea r10, [cache_scan_buf] ; current tooth
    
.parse_dent:
    cmp r15, 0
    jle .scan_loop
    
    movzx r11, word [r10 + 16] ; d_reclen
    
    ; Check d_type == DT_REG (8)
    mov al, [r10 + 18]
    cmp al, 8
    jne .next_dent
    
    ; Check hidden file
    mov al, [r10 + 19]
    cmp al, '.'
    je .next_dent
    
    ; Construct path
    lea rdi, [cache_scan_buf + 2048]
    mov rsi, r14
.copy_root:
    mov al, [rsi]
    test al, al
    jz .copy_filename
    mov [rdi], al
    inc rdi
    inc rsi
    jmp .copy_root
.copy_filename:
    lea rsi, [r10 + 19]
.copy_path:
    mov al, [rsi]
    mov [rdi], al
    test al, al
    jz .do_cache
    inc rdi
    inc rsi
    jmp .copy_path
    
.do_cache:
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    
    lea rdi, [cache_scan_buf + 2048]
    mov rsi, r12        ; vhost_id
    mov rdx, [rsp + 64] ; doc_root length is at saved rcx (8 pushes * 8 = 64 bytes offset)
    call cache_one_file
    
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    
.next_dent:
    add r10, r11
    sub r15, r11
    jmp .parse_dent
    
.close_dir:
    mov rax, 3
    mov rdi, r13
    syscall
    
.next_vhost_pop:
    pop rcx
.next_vhost:
    inc r12d
    jmp .vhost_loop
    
.scan_done:
    pop rbx
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    ret

; =====================================================================
; AF_XDP RAW TCP/IP EVENT LOOP
; Minimal TCP stack: SYN-ACK, HTTP GET response, FIN-ACK
; =====================================================================

xdp_event_loop:
    ; Poll the RX ring for incoming packets
    ; RX ring structure: producer(4B), pad(4B), consumer(4B), pad(4B), flags(4B), pad(12B), desc[]
    ; Each descriptor: addr(u64) + len(u32) + options(u32) = 16 bytes
    mov rcx, [xdp_rx_ring]
    mov eax, [rcx]              ; producer index
    mov ebx, [xdp_rx_cons]      ; our consumer index
    cmp eax, ebx
    je .xdp_no_packet

    ; Got a packet! Read the descriptor
    mov edx, ebx
    and edx, 511                ; mask = ring_size - 1
    shl edx, 4                  ; * 16 (descriptor size)
    add edx, 64                 ; skip ring header
    mov rsi, [rcx + rdx]        ; UMEM offset of packet
    mov r8d, [rcx + rdx + 8]    ; packet length

    ; Get packet pointer = UMEM base + offset
    add rsi, [xdp_umem_ptr]

    ; Advance consumer
    inc ebx
    mov [xdp_rx_cons], ebx
    mov [rcx + 8], ebx          ; update consumer in ring

    ; Minimum packet: Eth(14) + IP(20) + TCP(20) = 54 bytes
    cmp r8d, 54
    jl .xdp_recycle_frame

    ; === Parse Ethernet Header (14 bytes) ===
    ; [0-5] dst mac, [6-11] src mac, [12-13] ethertype
    cmp word [rsi + 12], 0x0008  ; ETH_P_IP (0x0800 in network byte order = 0x0008 LE)
    jne .xdp_recycle_frame

    ; === Parse IP Header (starts at offset 14) ===
    lea r9, [rsi + 14]          ; r9 = IP header start
    movzx eax, byte [r9]        ; version + IHL
    and eax, 0x0F                ; IHL (header length in 32-bit words)
    shl eax, 2                   ; IHL * 4 = IP header bytes
    mov r10d, eax                ; r10d = IP header length

    cmp byte [r9 + 9], 6        ; protocol = TCP?
    jne .xdp_recycle_frame

    ; Save IP addresses for response
    mov eax, [r9 + 12]          ; srcIP
    mov ebx, [r9 + 16]          ; dst IP

    ; === Parse TCP Header (starts at IP + IHL) ===
    lea r11, [r9 + r10]         ; r11 = TCP header start
    movzx ecx, word [r11]       ; src port
    movzx edx, word [r11 + 2]   ; dst port

    ; Check TCP flags at offset 13
    movzx edi, byte [r11 + 13]  ; TCP flags

    ; --- Handle SYN (flags & 0x02, but NOT ACK) ---
    test edi, 0x02              ; SYN?
    jz .xdp_check_fin
    test edi, 0x10              ; already ACK? (SYN-ACK from us)
    jnz .xdp_check_data

    ; Build SYN-ACK response
    ; Swap MACs in response
    lea rdi, [xdp_pkt_buf]
    ; Copy src MAC -> dst MAC
    mov rax, [rsi + 6]          ; src MAC (6 bytes, read 8)
    mov [rdi], rax               ;  -> new dst MAC
    mov rax, [rsi]              ; dst MAC (6 bytes, read 8)
    mov [rdi + 6], rax           ;  -> new src MAC
    mov word [rdi + 12], 0x0008 ; ETH_P_IP

    ; IP header (20 bytes, minimum)
    lea r15, [rdi + 14]         ; r15 = IP header in response
    mov byte [r15], 0x45        ; version=4, IHL=5
    mov byte [r15 + 1], 0      ; DSCP/ECN
    mov word [r15 + 2], 0       ; total length (filled later)
    mov word [r15 + 4], 0       ; identification
    mov word [r15 + 6], 0x0040  ; flags: Don't Fragment
    mov byte [r15 + 8], 64      ; TTL
    mov byte [r15 + 9], 6       ; protocol: TCP
    mov word [r15 + 10], 0      ; checksum (computed later)
    mov [r15 + 12], ebx         ; src IP = original dst
    mov [r15 + 16], eax         ; dst IP = original src

    ; TCP header (20 bytes + MSS option = 24 bytes)
    lea r14, [r15 + 20]         ; r14 = TCP header in response
    mov [r14], dx               ; src port = original dst port
    mov [r14 + 2], cx           ; dst port = original src port

    ; Our initial sequence number = 1 (simple)
    mov dword [r14 + 4], 0x01000000  ; seq=1 in network byte order
    mov dword [xdp_tcp_seq], 1

    ; ACK = their seq + 1
    mov eax, [r11 + 4]          ; their seq (network byte order)
    bswap eax
    inc eax
    mov [xdp_tcp_ack], eax
    bswap eax
    mov [r14 + 8], eax          ; ack number

    mov byte [r14 + 12], 0x60  ; data offset = 6 (24 bytes / 4), no reserved
    mov byte [r14 + 13], 0x12  ; flags: SYN + ACK
    mov word [r14 + 14], 0xFFFF ; window size = 65535 (network byte order swap later)
    ; Actually use 0xFFFF in LE which is big-endian 0xFFFF = 65535, correct
    mov word [r14 + 16], 0      ; checksum (computed later)
    mov word [r14 + 18], 0      ; urgent point

    ; MSS option: kind=2, len=4, MSS=1460 (0x05B4)
    mov byte [r14 + 20], 2      ; kind = Maximum Segment Size
    mov byte [r14 + 21], 4      ; length = 4
    mov word [r14 + 22], 0xB405 ; MSS=1460 in network byte order

    ; Set IP total length: 20 (IP) + 24 (TCP + MSS) = 44
    mov word [r15 + 2], 0x2C00  ; 44 in big-endian

    ; Compute IP checksum
    mov rdi, r15
    mov ecx, 20
    call ip_checksum
    mov [r15 + 10], ax

    ; Compute TCP checksum (pseudo-header + TCP segment)
    mov rdi, r14
    mov ecx, 24                 ; TCP header + MSS option
    mov eax, [r15 + 12]         ; srcIP
    mov ebx, [r15 + 16]         ; dst IP
    call tcp_checksum
    mov [r14 + 16], ax

    ; Total packet: 14 + 44 = 58 bytes
    mov r8d, 58
    jmp .xdp_send_packet

.xdp_check_fin:
    ; --- Handle FIN (flags & 0x01) ---
    test edi, 0x01              ; END?
    jz .xdp_check_data

    ; Build FIN-ACK response (same header construction, just different flags)
    lea rdi, [xdp_pkt_buf]
    ; Swap MACs
    mov rax, [rsi + 6]
    mov [rdi], rax
    mov rax, [rsi]
    mov [rdi + 6], rax
    mov word [rdi + 12], 0x0008

    lea r15, [rdi + 14]
    mov byte [r15], 0x45
    mov byte [r15 + 1], 0
    mov word [r15 + 2], 0x2800  ; 40 bytes total (20 IP + 20 TCP)
    mov word [r15 + 4], 0
    mov word [r15 + 6], 0x0040
    mov byte [r15 + 8], 64
    mov byte [r15 + 9], 6
    mov word [r15 + 10], 0
    mov [r15 + 12], ebx
    mov [r15 + 16], eax

    lea r14, [r15 + 20]
    mov [r14], dx
    mov [r14 + 2], cx

    ; Seq = our current seq
    mov eax, [xdp_tcp_seq]
    bswap eax
    mov [r14 + 4], eax

    ; ACK = their seq + 1 (FIN consumes a sequence number)
    mov eax, [r11 + 4]
    bswap eax
    ; Get payload length for proper ACK
    movzx ecx, word [r9 + 2]   ; IP total length (big-endian)
    xchg cl, ch
    sub ecx, r10d               ; subtract IP header
    movzx edx, byte [r11 + 12] ; TCP data offset
    shr edx, 4
    shl edx, 2
    sub ecx, edx                ; payload length
    add eax, ecx
    inc eax                     ; +1 for END
    mov [xdp_tcp_ack], eax
    bswap eax
    mov [r14 + 8], eax

    mov byte [r14 + 12], 0x50  ; data offset = 5 (20 bytes)
    mov byte [r14 + 13], 0x11  ; flags: END + ACK
    mov word [r14 + 14], 0xFFFF
    mov word [r14 + 16], 0
    mov word [r14 + 18], 0

    ; IP checksum
    mov rdi, r15
    mov ecx, 20
    call ip_checksum
    mov [r15 + 10], ax

    ; Swap IPs back for ports (they were swapped in header)
    mov eax, [r15 + 12]
    mov ebx, [r15 + 16]
    ; TCP checksum
    mov rdi, r14
    mov ecx, 20
    call tcp_checksum
    mov [r14 + 16], ax

    mov r8d, 54                 ; 14 + 20 + 20
    jmp .xdp_send_packet

.xdp_check_data:
    ; --- Handle data packet (PSH+ACK with HTTP GET) ---
    test edi, 0x10              ; ACK flag set?
    jz .xdp_recycle_frame

    ; Calculate payload offset and length
    movzx r13d, byte [r11 + 12] ; TCP data offset (upper 4 bits)
    shr r13d, 4
    shl r13d, 2                  ; TCP header length in bytes

    ; Payload length = IP total length - IP header - TCP header
    movzx eax, word [r9 + 2]    ; IP total length (big-endian)
    xchg al, ah
    sub eax, r10d                ; -IP header
    sub eax, r13d                ; -TCP header

    cmp eax, 0
    jle .xdp_send_ack_only       ; Pure ACK (no data), just acknowledge

    ; Check for "GET " at start of payload
    lea r12, [r11 + r13]        ; r12 = HTTP payload start
    cmp dword [r12], 0x20544547 ; "GET " in little-endian
    jne .xdp_send_ack_only

    ; === HTTP GET detected! Build response ===
    ; Update ACK number: their seq + payload length
    mov eax, [r11 + 4]         ; their seq (network byte order)
    bswap eax
    ; Calculate total data received
    movzx ecx, word [r9 + 2]
    xchg cl, ch
    sub ecx, r10d
    sub ecx, r13d               ; payload length
    add eax, ecx
    mov [xdp_tcp_ack], eax

    ; Increment our seq
    mov ecx, [xdp_tcp_seq]      ; will be updated after we send

    ; Build the response packet with JIT response embedded
    lea rdi, [xdp_pkt_buf]
    ; Swap MACs
    mov rax, [rsi + 6]
    mov [rdi], rax
    mov rax, [rsi]
    mov [rdi + 6], rax
    mov word [rdi + 12], 0x0008

    ; IP header
    lea r15, [rdi + 14]
    mov byte [r15], 0x45
    mov byte [r15 + 1], 0
    ; Total length filled after we know payload size
    mov word [r15 + 4], 0
    mov word [r15 + 6], 0x0040
    mov byte [r15 + 8], 64
    mov byte [r15 + 9], 6
    mov word [r15 + 10], 0
    ; Swap src/dst IP
    mov eax, [r9 + 16]          ; original dst IP -> our src
    mov [r15 + 12], eax
    mov eax, [r9 + 12]          ; original src IP -> our dst
    mov [r15 + 16], eax

    ; TCP header
    lea r14, [r15 + 20]
    movzx eax, word [r11 + 2]   ; their dst port -> our src port
    mov [r14], ax
    movzx eax, word [r11]       ; their src port -> our dst port
    mov [r14 + 2], ax

    ; Seq = our current seq
    mov eax, ecx
    bswap eax
    mov [r14 + 4], eax

    ; ACK = updated ack
    mov eax, [xdp_tcp_ack]
    bswap eax
    mov [r14 + 8], eax

    mov byte [r14 + 12], 0x50  ; data offset = 5
    mov byte [r14 + 13], 0x18  ; PSH+ACK
    mov word [r14 + 14], 0xFFFF ; window
    mov word [r14 + 16], 0      ; checksum (later)
    mov word [r14 + 18], 0

    ; Copy HTTP response body (msg_auth_ok) into the packet after TCP header
    lea rdi, [r14 + 20]        ; HTTP payload starts after TCP header
    mov rsi, msg_auth_ok
    mov ecx, msg_auth_ok_len
    ; Update our seq for next packet
    add [xdp_tcp_seq], ecx
    ; Copy the response
    push rcx
    rep movsb
    pop rcx

    ; Set IP total length: 20 (IP) + 20 (TCP) + payload_len
    lea eax, [ecx + 40]        ; Total IP = 40 + HTTP len
    xchg al, ah                ; to big-endian
    mov [r15 + 2], ax

    ; IP checksum
    push rcx
    mov rdi, r15
    mov ecx, 20
    call ip_checksum
    mov [r15 + 10], ax
    pop rcx

    ; TCP checksum (TCP header 20 bytes + payload)
    push rcx
    mov eax, [r15 + 12]        ; srcIP
    mov ebx, [r15 + 16]        ; dst IP
    lea ecx, [ecx + 20]        ; TCP segment length = 20 + payload
    mov rdi, r14
    call tcp_checksum
    mov [r14 + 16], ax
    pop rcx

    ; Total packet: 14 (Eth) + 20 (IP) + 20 (TCP) + payload
    lea r8d, [ecx + 54]
    jmp .xdp_send_packet

.xdp_send_ack_only:
    ; Build a pure ACK (no data)
    lea rdi, [xdp_pkt_buf]
    ; Swap MACs
    mov rax, [rsi + 6]
    mov [rdi], rax
    mov rax, [rsi]
    mov [rdi + 6], rax
    mov word [rdi + 12], 0x0008

    lea r15, [rdi + 14]
    mov byte [r15], 0x45
    mov byte [r15 + 1], 0
    mov word [r15 + 2], 0x2800  ; 40 bytes
    mov word [r15 + 4], 0
    mov word [r15 + 6], 0x0040
    mov byte [r15 + 8], 64
    mov byte [r15 + 9], 6
    mov word [r15 + 10], 0
    ; Swap IPs
    mov eax, [r9 + 16]
    mov [r15 + 12], eax
    mov eax, [r9 + 12]
    mov [r15 + 16], eax

    lea r14, [r15 + 20]
    movzx eax, word [r11 + 2]
    mov [r14], ax
    movzx eax, word [r11]
    mov [r14 + 2], ax

    mov eax, [xdp_tcp_seq]
    bswap eax
    mov [r14 + 4], eax

    ; ACK their data
    mov eax, [r11 + 4]
    bswap eax
    movzx ecx, word [r9 + 2]
    xchg cl, ch
    sub ecx, r10d
    sub ecx, r13d
    add eax, ecx
    mov [xdp_tcp_ack], eax
    bswap eax
    mov [r14 + 8], eax

    mov byte [r14 + 12], 0x50
    mov byte [r14 + 13], 0x10  ; ACK only
    mov word [r14 + 14], 0xFFFF
    mov word [r14 + 16], 0
    mov word [r14 + 18], 0

    mov rdi, r15
    mov ecx, 20
    call ip_checksum
    mov [r15 + 10], ax

    mov eax, [r15 + 12]
    mov ebx, [r15 + 16]
    mov rdi, r14
    mov ecx, 20
    call tcp_checksum
    mov [r14 + 16], ax

    mov r8d, 54
    jmp .xdp_send_packet

.xdp_send_packet:
    ; Submit the response on the TX ring
    ; r8d = packet length, xdp_pkt_buf has the packet

    ; First, copy packet into a UMEM frame for TX
    ; Use frame 511 (last frame) as TX buffer
    mov rdi, [xdp_umem_ptr]
    add rdi, 511 * 4096         ; last frame
    lea rsi, [xdp_pkt_buf]
    mov ecx, r8d
    push r8
    rep movsb
    pop r8

    ; Write TX descriptor
    mov rcx, [xdp_tx_ring]
    mov eax, [xdp_tx_prod]
    mov edx, eax
    and edx, 511
    shl edx, 4
    add edx, 64                 ; skip ring header
    mov dword [rcx + rdx], 511 * 4096   ; UMEM offset
    mov [rcx + rdx + 8], r8d    ; packet length
    inc eax
    mov [xdp_tx_prod], eax
    mov [rcx], eax              ; update producer in ring

    ; Kick the kernel to send: sendto(xsk_fd, NULL, 0, MSG_DONTWAIT, NULL, 0)
    mov rax, 44                 ; sys_sendto
    mov edi, [xsk_fd]
    xor rsi, rsi
    xor rdx, rdx
    mov r10, 0x40               ; MSG_DONTWAIT
    xor r8, r8
    xor r9, r9
    syscall

.xdp_recycle_frame:
    ; Recycle consumed frames back to FILL ring
    ; (simplified: re-fill one frame per consumed packet)
    jmp xdp_event_loop

.xdp_no_packet:
    ; No packets: poll with short timeout to avoid busy-wait
    ; poll(fds=[{fd=xsk_fd, events=POLLIN}], nfds=1, timeout=1)
    sub rsp, 8                  ; struct pollfd
    mov edi, [xsk_fd]
    mov [rsp], edi              ; fd
    mov word [rsp + 4], 1       ; events = POLLIN
    mov word [rsp + 6], 0       ; rewinds
    mov rax, 7                  ; sys_poll
    lea rdi, [rsp]
    mov rsi, 1                  ; nfds = 1
    mov rdx, 1                  ; timeout = 1ms
    syscall
    add rsp, 8
    jmp xdp_event_loop

; =====================================================================
; CHECKSUM ROUTINES for raw TCP/IP
; =====================================================================

; ip_checksum: Compute IP header checksum
; Input: rdi = IP header pointer, ecx = header length (bytes)
; Output: ax = checksum (network byte order)
; Clobbers: rdx, rcx, rsi
ip_checksum:
    xor edx, edx               ; accumulator
    shr ecx, 1                  ; byte count -> word count
.ip_cksum_loop:
    movzx eax, word [rdi]
    add edx, eax
    add rdi, 2
    dec ecx
    jnz .ip_cksum_loop
    ; Fold 32-bit sum to 16-bit
    mov eax, edx
    shr eax, 16
    and edx, 0xFFFF
    add eax, edx
    ; Add carry
    mov edx, eax
    shr edx, 16
    add eax, edx
    not ax                      ; one's complement
    ret

; tcp_checksum: Compute TCP checksum with pseudo-header
; Input: rdi = TCP segment pointer, ecx = TCP segment length (header + data)
;        eax = src IP (network byte order), ebx = dst IP (network byte order)
; Output: ax = checksum (network byte order)
; Clobbers: rdx, rcx, rsi, r8
tcp_checksum:
    push rcx
    ; Start with pseudo-header sum
    xor edx, edx

    ; Add source IP (2 words)
    movzx r8d, ax               ; low 16 bits of src IP
    add edx, r8d
    shr eax, 16
    add edx, eax

    ; Add dest IP (2 words)
    movzx r8d, bx
    add edx, r8d
    shr ebx, 16
    add edx, ebx

    ; Add protocol (6 = TCP) in network byte order = 0x0600
    add edx, 0x0600

    ; Add TCP length in network byte order
    mov eax, ecx
    xchg al, ah                 ; to big-endian
    movzx eax, ax
    add edx, eax

    ; Now add TCP segment data
    pop rcx
    push rcx
    shr ecx, 1                  ; word count
.tcp_cksum_loop:
    movzx eax, word [rdi]
    add edx, eax
    add rdi, 2
    dec ecx
    jnz .tcp_cksum_loop

    ; Handle odd byte
    pop rcx
    test ecx, 1
    jz .tcp_cksum_fold
    movzx eax, byte [rdi]
    add edx, eax

.tcp_cksum_fold:
    ; Fold 32-bit sum
    mov eax, edx
    shr eax, 16
    and edx, 0xFFFF
    add eax, edx
    mov edx, eax
    shr edx, 16
    add eax, edx
    not ax
    ret
section .note.GNU-stack noalloc noexec nowrite progbits
    db 0
