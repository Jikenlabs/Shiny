# Changelog

All notable changes to this project will be documented in this file.

## [v0.2.0] - 2026-04-11

### Added
- **TCP Proxy Target:** Unified Keep-Alive testing suite strictly via `Splice Zero-Copy` TCP backend (`/api/`) for seamless pipeline orchestration.
- **Documentation:** Added clear technical documentation detailing `worker_processes` scaling alongside the brand new `SHINY_TLS_THREADS` tuning parameter for maximizing parallelism.
- **Testing:** Full pipeline stabilization by killing existing background instances recursively before launching the native Python test suite.

### Refactored
- **Proxy Dispatcher:** Ground-up optimization of the internal proxy request pointer logic (`slot_proxy_req_ptr`), resolving legacy loop pointer leakage bugs during multiplexed HTTP/1.1 pipelining.
- **Asynchronous IO (io_uring):** Eliminated blocking synchronous edge-cases for AF_UNIX routes in favor of highly optimized pure asynchronous queue dispatches (`uring_submit_proxy_send_sqe`).
- **Memory Security:** Enforced strict W^X (Write XOR Execute) memory protection paradigms globally for dynamically handled arrays, reinforcing against payload injection attacks.
- **Rebranding:** Renamed main executable to `Shiny` preserving core legacy load balancing directives.

### Fixed
- **CI/CD Reliability:** Solved sporadic Keep-Alive hangs and 502 Bad Gateway deadlocks in GitHub Actions Ubuntu VMs by properly validating asynchronous responses.
- **Compiler Hardening:** Eliminated GCC `-Wmissing-field-initializers` compiler warnings inside the TLS handshake loop.
