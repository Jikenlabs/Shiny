CC = gcc
NASM = nasm
CFLAGS = -O2 -Wall -Wextra -Wformat -Wformat-security -fstack-protector-strong -fstack-clash-protection -D_FORTIFY_SOURCE=2 -fPIC
LDFLAGS = -nostartfiles -no-pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack
LIBS = -lssl -lcrypto
NASMFLAGS = -f elf64

OBJS = server.o tls_handshake.o nginx_parser.o
BIN = Shiny

.PHONY: all clean setcap

all: $(BIN)

$(BIN): $(OBJS)
	@echo "🔗 Édition des liens avec OpenSSL..."
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)
	@echo "✅ Serveur compilé et prêt à l'emploi !"

server.o: server.asm
	@echo "🔨 Compilation de server.asm..."
	$(NASM) $(NASMFLAGS) $< -o $@

tls_handshake.o: tls_handshake.c
	@echo "🔨 Compilation de tls_handshake.c..."
	$(CC) $(CFLAGS) -c $< -o $@

nginx_parser.o: nginx_parser.c
	@echo "🔨 Compilation de nginx_parser.c..."
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	@echo "🗑️ Nettoyage des fichiers compilés..."
	rm -f $(OBJS) $(BIN)

setcap: $(BIN)
	@echo "🗝️ Injection des capacités Kernel (Zero-Copy / io_uring)..."
	sudo setcap cap_net_bind_service,cap_net_raw,cap_ipc_lock+ep ./$(BIN)
	@echo "✅ Capacités injectées !"
