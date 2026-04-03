# Shiny Configuration Guide

This guide details how to configure the **Shiny Assembly Server** utilizing its Nginx-compatible syntax reader (`shiny.conf`).

Shiny reads routing definitions at startup from the main configuration file to dictate Reverse Proxy mappings and TLS initialization constants.

## Basic Structure (`shiny.conf`)

By default, Shiny expects `shiny.conf` to be located in the working directory when executed.

```nginx
; Global Server Definitions
server {
    listen 8080;
    server_name localhost;

    ; Static routing block
    location / {
        root www/vhost1/;
        index index.html;
    }

    ; Proxy Pass Block (Standard TCP)
    location /api/ {
        proxy_pass http://127.0.0.1:3005;
        keepalive_requests 100;
        proxy_http_version 1.1;
    }

    ; Proxy Pass Block (UNIX Socket)
    location /api_sock/ {
        proxy_pass http://unix:/path/to/project/conf.d/node.sock;
    }
}
```

## Supported Directives

### 1. `listen`
- **Description:** Port to listen on.
- **Example:** `listen 8080;` or `listen 443 ssl;`

### 2. `server_name`
- **Description:** Hostname matching for specific `server` blocks.
- **Example:** `server_name test.local;`

### 3. `location`
- **Description:** Route matching for a particular HTTP sub-path.
- **Example:** `location /static/ { ... }`

#### Sub-Directives inside `location`:

- `root <path>;`
  Denotes a directory out of which static files are served directly using Zero-Copy mechanics.
- `index <file_name>;`
  The default file to deliver when the path strictly requests the root of that location.
- `proxy_pass <Target URI>;`
  The backend endpoint to route Layer 7 payload traffic. Supports TCP addresses (`http://127.0.0.1:8000`) and native sockets (`http://unix:/path/to/sock.sock`).
- `keepalive_requests <int>;`
  The threshold for multiplexing connections back to the proxy targets before closing the `AF_INET` or `AF_UNIX` upstream handle.

### 4. `worker_processes`
- **Description:** Defines the number of worker processes spawned by the server. Each worker is isolated and runs its own dedicated TLS context (`tls_worker_init`). This dictates the level of parallelization for both standard connections and expensive TLS handshakes. It must be declared in the global scope (outside `server` blocks). Set to `0` for auto-detection based on available CPU cores.
- **Example:** `worker_processes 8;`


## TLS Considerations

If you intend to test HTTPS connections or bind a production cluster with TLS enabled, you must specify `ssl` on the listen block and provide certificates inside a dedicated `tls/` or `conf.d/` directory.

```nginx
server {
    listen 443 ssl;
    ssl_certificate tls/server.crt;
    ssl_certificate_key tls/server.key;

    location / {
        root www/secure/;
    }
}
```

### TLS Handshake Threads (`SHINY_TLS_THREADS`)

While `worker_processes` scales the main event loop, the expensive operations of establishing TLS 1.3 handshakes are offloaded to dedicated background threads within each worker. By default, **4 TLS threads** are spawned per worker. You can override this limit (up to a maximum of 16) using the `SHINY_TLS_THREADS` environment variable when launching the server:

```bash
# Force 2 TLS handshake threads per worker
SHINY_TLS_THREADS=2 ./Shiny
```

> [!CAUTION]
> The internal `tls_handshake.c` logic dynamically maps to OpenSSL implementations. Do not use extremely specific cypher payloads unless your OpenSSL environment aligns natively. Use modern default curve TLS settings.
