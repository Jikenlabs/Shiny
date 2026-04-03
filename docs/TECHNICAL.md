# Technical Architecture

**Overview of Shiny's High-Performance HTTP Assembly Engine**

This document outlines the core technical architecture of Shiny, a custom-built, extreme-performance API Gateway and Reverse Proxy written extensively in x86_64 Assembly. It operates directly at the kernel interface level to bypass typical runtime overheads.

## 🏗️ Core Design Philosophy

The primary objective of this architecture is maximizing network throughput while strictly maintaining single-digit microsecond latencies per request, challenging the established limits of robust proxy solutions like Nginx.

### 1. ⚙️ `io_uring` and Kernel Interaction
Unlike tradition edge servers that rely on `select`, `poll`, or even `epoll`, Shiny fundamentally integrates with the **`io_uring`** asynchronous I/O API provided by the modern Linux kernel.

> [!TIP]
> **Why `io_uring`?** By utilizing Submission Queue (SQ) and Completion Queue (CQ) ring buffers shared between user-space and kernel-space, Shiny completely eliminates costly system call overhead for every socket read or file access.

- **Defer Taskrun**: Polling utilizes advanced `defer taskrun` optimizations.
- **Batched Submissions**: HTTP request streams and file descriptor statuses are batched prior to notifying the kernel.

### 2. ⚡ Zero-Copy Network Operations (`IORING_OP_SEND_ZC`)
Shiny abandons standard `send()` buffers. Instead, requests routed as static files (or pure payload deliveries) interface directly with the Network Interface Card (NIC).
Memory pages loaded from disk are mapped, and pointers are forwarded through `io_uring` zero-copy protocols directly to the network stack, entirely bypassing CPU memory-copy routines.

### 3. 🧠 SIMD HTTP Parsing
To achieve extreme parsing efficiency, Shiny utilizes **AVX2 / SIMD** instructions to parse incoming Nginx-style headers.
Rather than processing HTTP headers character-by-character, 256-bit wide registers compare up to 32 characters simultaneously to instantly locate HTTP methods, `\r\n` boundaries, and target routes.

### 4. 🔥 Upstream Load Balancing (Warm Pools)
Shiny serves as a highly scalable Layer 7 load balancer.
It maintains multiple persistent connection pools (**Warm Pools**) to designated upstreams:
- Native UNIX Domain Sockets (`AF_UNIX`) for localized backends (e.g., local Node.js or Python UNIX daemons).
- Traditional TCP Sockets (`AF_INET`).

> [!WARNING]
> Modifying the Assembly logic responsible for the Round-Robin/IP-Hash upstream routing algorithms requires strict register state preservation (specifically `r12`-`r15`), as the loop heavily relies on these for non-volatile connection pointers during socket multiplexing.

### 5. 🔒 TLS Termination (C Extension)
While the vast majority of the core loop and kernel interaction is written natively in Assembly, TLS handshake negotiation relies on standard `OpenSSL` hooks wrapped in a compact C interface (`tls_handshake.c`). This avoids re-implementing cryptography natively while securely integrating modern SSL endpoints directly into the `io_uring` completion loop.

## Architecture Diagram

*(If you have cloned the repository, please view `shiny_server_arch.excalidraw` included in this folder for the complete visual representation of the thread scaling model and ring buffers).*
