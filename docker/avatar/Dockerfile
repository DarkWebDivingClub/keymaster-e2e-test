FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-client gnupg procps python3-minimal gnutls-bin p11-kit opensc openssl \
    && rm -rf /var/lib/apt/lists/*
COPY keymaster-avatar /usr/local/bin/keymaster-avatar
COPY km-ssh-sa /usr/local/bin/km-ssh-sa
COPY km-gpg-sa /usr/local/bin/km-gpg-sa
COPY km-nostr-sa /usr/local/bin/km-nostr-sa
COPY km-x509-sa /usr/local/bin/km-x509-sa
COPY scd-shim /usr/local/bin/scd-shim
# PKCS#11 module for X.509 keys, at the package path and registered with
# p11-kit the way the package does it (debian/keymaster.module)
COPY libkm_pkcs11_x509.so /usr/lib/keymaster-avatar/lib/libkm_pkcs11_x509.so
RUN mkdir -p /usr/share/p11-kit/modules && \
    printf 'module: /usr/lib/keymaster-avatar/lib/libkm_pkcs11_x509.so\ncritical: no\n' \
    > /usr/share/p11-kit/modules/keymaster.module
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/keymaster-avatar /usr/local/bin/km-ssh-sa \
    /usr/local/bin/km-gpg-sa /usr/local/bin/km-nostr-sa /usr/local/bin/km-x509-sa \
    /usr/local/bin/scd-shim \
    /usr/local/bin/entrypoint.sh && \
    mkdir -p /var/lib/keymaster-avatar
ENTRYPOINT ["entrypoint.sh"]
