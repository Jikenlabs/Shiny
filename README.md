<div align="center">
  <h1>🚀 Shiny Server</h1>
  <p><strong>A Hyper-Optimized, Assembly-based HTTP Proxy & Load Balancer</strong></p>
  
  [![Build Status](https://github.com/Jikenlabs/Shiny/actions/workflows/ci.yml/badge.svg)](https://github.com/Jikenlabs/Shiny/actions)
  [![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://github.com/Jikenlabs/Shiny/blob/main/LICENSE)
  [![Platform](https://img.shields.io/badge/Platform-Linux%20x86__64-blue.svg)](#)
</div>

---

> [!IMPORTANT]
> **Shiny** is a high-performance HTTP web server and robust multi-upstream load balancer written purely in **x86_64 Assembly** with C extensions for TLS (`OpenSSL`) and configuration parsing (`Nginx standards`). It heavily utilizes Linux native primitives like `io_uring` and Zero-Copy to achieve extreme throughput and sub-millisecond latency. 

## ✨ Features

- **⚡ Blazing Fast:** Written primarily in highly-optimized x86_64 Assembly.
- **🔄 Async I/O Native:** Native Linux `io_uring` for true asynchronous file and network operations without the overhead of standard threads or `epoll`.
- **✂️ Zero-Copy Networking:** Implements `IORING_OP_SEND_ZC` to bypass kernel networking buffers and pass memory directly to the NIC driver.
- **🚥 Smart Load Balancing:** Round-Robin, IP Hash, and Least Connections support across mixed upstream architectures (TCP and UNIX Sockets).
- **🗃️ Persistent Warm Pools:** Pre-warmed upstream connection pools to eliminate TCP handshake tail latency on proxy routing.
- **🛡️ Secure Native TLS:** C-based `OpenSSL` bindings injected into the Assembly pipeline for encrypted transport. Features an intelligent **Bifurcated Architecture** ensuring hardware `kTLS` Offload Fast-Paths when available, and gracefully degrading to a C-based `socketpair` thread pool for **TLS 1.3** Userspace Fallbacks without interrupting the Zero-Copy AVX2 async engine.

---

## 🛠️ Quickstart

### Libraries & Dependencies
Shiny is designed to be extraordinarily close to the bare metal, requiring almost no external software. The core Engine strictly relies on standard Linux Kernel features (>= 5.11 for advanced `io_uring` and `kTLS`).

However, for compiling the server and its C extensions (specifically the TLS Handshake and Nginx-compatible Config Parser), you will need the following tools:
- **`make`**: Standard GNU Make tool to run the build pipeline.
- **`nasm`**: Netwide Assembler to compile the core x86_64 architecture.
- **`gcc`**: The GNU Compiler Collection for compiling the C-based OpenSSL bindings.
- **`libssl-dev`** (or `openssl-devel` on RHEL-based systems): The critical development headers required to link the encrypted native TLS transport functions (`-lssl -lcrypto`).
- Python 3.x (Optional, specifically for running the TDD `pytest` suite).

### Build & Run

Clone the repository and build the architecture using `make`:

```bash
git clone https://github.com/Jikenlabs/Shiny.git
cd Shiny

# Compile the assembly server and link dependencies
make

# The server requires some runtime directories
mkdir -p www/vhost1
mkdir -p conf.d
echo "Hello World" > www/vhost1/index.html

# Run the Shiny Gateway
./Shiny
```

> [!NOTE]
> Ensure that a `shiny.conf` routing configuration file is properly set up in the working directory before executing the binary. See [Configuration Documentation](./docs/CONFIGURATION.md) for more details.

### 🐳 Docker Deployment

For instant deployment without compiling locally, Shiny includes a multi-stage `scratch` Dockerfile resulting in a hyper-lightweight image (~3.6MB) with absolutely zero privileges.

```bash
# Build the extremely lightweight image
docker build -t shiny-server .

# Run the server in standard fallback mode (Synchronous Accept)
docker run -p 8080:8080 shiny-server
```

> [!IMPORTANT]
> **Maximum Performance (`io_uring`) under Docker**  
> By default, Docker's `seccomp` security profile blocks the `io_uring_setup` system call, forcing Shiny to gracefully downgrade to a slower, synchronous `accept4` fallback mode.  
> To unlock the raw asynchronous power of the kernel and enable Zero-Copy networking inside the container, you **must** bypass this restriction:
> ```bash
> docker run --security-opt seccomp=unconfined -p 8080:8080 shiny-server
> ```
> This unlocks the full `io_uring` ring buffers and Multi-shot Accept capabilities shown during a native bare-metal execution.

## 📚 Documentation

For an in-depth understanding of the engine and how to deploy it:

- [**Technical Architecture**](./docs/TECHNICAL.md): Learn about the core design, `io_uring` integration, ring buffers, and SIMD instruction acceleration.
- [**Configuration Guide**](./docs/CONFIGURATION.md): How to craft `shiny.conf` for reverse proxying, TLS binding, and load balancing rules.
- [**Benchmarking Guide**](./docs/BENCHMARKING.md): Scripts and instructions to extract CPU, Memory, and RPS data to generate beautiful performance infographics.


---

## 🧪 Testing (TDD)

Shiny embraces Test-Driven Development. We provide a full Python `pytest` suite simulating concurrent connections, slowloris events, static artifact delivery, and routing rules:

```bash
# Setup python dependencies
pip install pytest requests

# Run proxy and standard conformance tests
pytest tests/test_shiny.py -v
```

---

## 🤝 Contributing

We welcome performance optimizations, new architecture pipelines, and security reviews. Please read the contributing guidelines (coming soon) and feel free to submit Pull Requests.

---

<div align="center">
  <i>Engineered for the theoretical limits of x86_64 architecture.</i>
</div>
