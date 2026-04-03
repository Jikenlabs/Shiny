#!/bin/bash
set -e

echo "🔨 Compilation de server.asm..."
nasm -f elf64 server.asm -o server.o

echo "🔨 Compilation de tls_handshake.c..."
gcc -c -O2 -o tls_handshake.o tls_handshake.c

echo "🔨 Compilation de nginx_parser.c..."
gcc -c -O2 -o nginx_parser.o nginx_parser.c

echo "🔗 Édition des liens avec OpenSSL..."
gcc -nostartfiles -no-pie -o server server.o tls_handshake.o nginx_parser.o -lssl -lcrypto

echo "🗝️ Injection des capacités Kernel (Zero-Copy / io_uring)..."
#sudo setcap cap_ipc_lock,cap_net_admin,cap_net_raw,cap_sys_admin+ep ./server

echo "✅ Serveur compilé et prêt à l'emploi !"
