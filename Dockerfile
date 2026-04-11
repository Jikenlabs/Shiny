# =========================================================
# ÉTAPE 1 : BUILDER (Alpine)
# =========================================================
FROM alpine:latest AS builder

# Pré-requis de compilation
RUN apk add --no-cache build-base nasm openssl-dev bsd-compat-headers linux-headers binutils upx

COPY . /src
WORKDIR /src

# Nettoyer et construire le binaire Shiny avec ses modules C
RUN make clean && make

# Déploiement de l'arborescence structurelle pour l'image 'scratch'
WORKDIR /scratch-root
RUN mkdir -p /scratch-root/app/www /scratch-root/app/conf.d \
    /scratch-root/lib /scratch-root/usr/lib

# Fichiers par défaut
RUN echo "<h1>Shiny Server works inside a Scratch Image!</h1>" > /scratch-root/app/www/index.html
RUN cp /src/Shiny /scratch-root/app/
RUN cp /src/shiny.conf /scratch-root/app/ || true

# Récupération stricte des bibliothèques dynamiques pour l'exécution Baremetal (OpenSSL et C runtime)
RUN cp /lib/ld-musl-x86_64.so.1 /scratch-root/lib/
RUN cp /usr/lib/libssl.so.3 /scratch-root/usr/lib/
RUN cp /usr/lib/libcrypto.so.3 /scratch-root/usr/lib/

# EXTRÊME OPTIMISATION : Suppression des tables de debug + Compression exécutive (UPX)
RUN strip -s /scratch-root/app/Shiny
RUN strip --strip-unneeded /scratch-root/usr/lib/libssl.so.3
RUN strip --strip-unneeded /scratch-root/usr/lib/libcrypto.so.3

RUN upx --lzma /scratch-root/app/Shiny
RUN upx --lzma /scratch-root/usr/lib/libcrypto.so.3

# =========================================================
# ÉTAPE 2 : EXÉCUTION (Scratch)
# =========================================================
FROM scratch

# Copie intégrale de l'environnement (Dossiers, libs, binaire)
COPY --from=builder /scratch-root /

WORKDIR /app
EXPOSE 8080

# Lancement natif du binaire (Aucun shell disponible)
CMD ["./Shiny"]
