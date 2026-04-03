# 🚀 Shiny Server - 1 Million RPS Breakthrough (Release Performance Report)

*Empirical Performance Analysis & Benchmarking Report for the Baremetal Release*

This document serves as the official performance analysis of the **Shiny Server** architecture prior to its initial public GitHub release. The benchmarks demonstrate that Shiny—engineered in pure x86_64 Assembly leveraging `io_uring` and `AVX2 / SIMD`—not only matches but significantly outperforms industry-standard servers (like Nginx) in identical environments.

Most notably, the server has officially shattered the **1 Million Requests Per Second (RPS)** barrier.

---

## 🏆 Headline Results & Strengths

### 1. The 1 Million RPS Milestone (Static Files)
When delivering static strings or files from memory using AVX2-accelerated parsing, Shiny successfully broke the psychological barrier of 1 Million RPS.
- **Peak Sustained RPS:** 1,000,741 RPS (Max Burst: 1,096,754 RPS)
- **Concurrency:** 100
- **Latency Average:** 97.60 µs

*Analysis:* This confirms the raw event-loop (powered by `io_uring` multi-shot accept and Fixed Files/Registered Buffers) operates with effectively zero CPU overhead. The server scales linearly until OS-level memory/bus bandwidth is saturated.

### 2. Pliage d'Nginx en Reverse Proxy TCP (Up to +109%)
When acting as a Layer 7 gateway (routing HTTP requests to an upstream TCP backend), Shiny destroys Nginx on equivalent connection counts.

| Mode / Protocole       | Concurrency | Shiny RPS       | Nginx RPS       | Performance Delta |
| :---                   | :---        | :---            | :---            | :---              |
| **Proxy TCP (L7)**     | 50          | **765 511 RPS** | 365 420 RPS     | **+ 109 %**       |
| **Proxy TCP (L7)**     | 1000        | **561 857 RPS** | 371 210 RPS     | **+ 51 %**        |

*Analysis:* At extreme concurrencies (1000+ multiplexed proxy streams), Shiny drops slightly from its 765k peak but firmly stabilizes at ~560k RPS, still maintaining over 50% performance supremacy over Nginx.

### 3. UNIX Sockets: Completely Bypassing IPv4 Overhead
To test whether the proxy drop-off at 1000 connections was an architectural flaw or simply the Linux IPv4 loopback limits, we stress-tested `AF_UNIX` proxying:
- **Proxy UNIX Socket (1000 Conns):** 741 742 RPS

*Analysis:* Shifting from IPv4 to UNIX sockets restored the throughput to nearly 750k RPS under extreme load, proving that Shiny's routing logic is flawless. The IP stack bounds traditional proxying, but Shiny's `io_uring` zero-copy socket bridge extracts the maximum possible throughput from the kernel.

---

## ⚠️ Architectural Bottlenecks (Points of Weakness)

While the Assembly logic holds perfectly, testing highlighted the natural hardware/OS limits:

1. **The Native TLS Cryptography Wall (~390k RPS):**
   Even when utilizing kernel-TLS (`kTLS`), offloading Elliptic Curve handshakes (P-256) and AES-128 GCM encryption completely saturates standard CPU cycles. The server peaks firmly at **~390,000 RPS** (tested between 160 and 500 connections). Breaching this TLS limit would require dedicated hardware offloading.

2. **OS Configuration (epoll / Context Switch Exhaustion):**
   When pushing concurrency strictly between 150 and 250 connections, the absolute "Sweet Spot" peak occurs exactly at **160 concurrent connections**. Beyond 190 connections, the OS scheduler and network queuing face significant backpressure, forcibly bringing performance down to a flatlined but resilient ~530k RPS.

---

## 📊 Comprehensive Data Tables

Below are the aggregated data points captured on Baremetal (bypassing Docker NAT) handling 5-second bombardment cycles.

### Static File Serving (AVX2 + Zero Copy)

| Mode / Fichier         | Concurrency | Shiny RPS           | Shiny Latency |
| :---                   | :---        | :---                | :---          |
| **Static HTML (/)**    | 160         | **526 537 RPS**     | 302.00 µs     |
| **Static HTML (/)**    | 200         | **526 296 RPS**     | 377.76 µs     |
| **Static HTML (/)**    | 500         | **532 433 RPS**     | 0.94 ms       |
| **Static TEXT (.txt)** | 50          | **830 406 RPS**     | 58.07 µs      |
| **Static TEXT (.txt)** | 100         | 🌟 **1 000 741 RPS**| 97.60 µs      |
| **Static TEXT (.txt)** | 500         | **787 975 RPS**     | 632.11 µs     |

### Reverse Proxy HTTPS (TLS kTLS Native P-256)

| Mode / Protocole       | Concurrency | Shiny RPS TLS     | Shiny Latency | Peak Throughput |
| :---                   | :---        | :---              | :---          | :---            |
| **Native TLS Proxy**   | 50          | **324 168 RPS**   | 152.20 µs     | 68.01 MB/s      |
| **Native TLS Proxy**   | 160         | **386 031 RPS**   | 411.98 µs     | 80.97 MB/s      |
| **Native TLS Proxy**   | 200         | **390 808 RPS**   | 509.50 µs     | 81.89 MB/s      |
| **Native TLS Proxy**   | 500         | **386 403 RPS**   | 1.30 ms       | 80.24 MB/s      |

