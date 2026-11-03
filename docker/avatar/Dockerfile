FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-client gnupg procps python3-minimal && rm -rf /var/lib/apt/lists/*
COPY keymaster-avatar /usr/local/bin/keymaster-avatar
COPY km-ssh-sa /usr/local/bin/km-ssh-sa
COPY km-gpg-sa /usr/local/bin/km-gpg-sa
COPY km-nostr-sa /usr/local/bin/km-nostr-sa
COPY km-x509-sa /usr/local/bin/km-x509-sa
COPY scd-shim /usr/local/bin/scd-shim
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/keymaster-avatar /usr/local/bin/km-ssh-sa \
    /usr/local/bin/km-gpg-sa /usr/local/bin/km-nostr-sa /usr/local/bin/km-x509-sa \
    /usr/local/bin/scd-shim \
    /usr/local/bin/entrypoint.sh && \
    mkdir -p /var/lib/keymaster-avatar
ENTRYPOINT ["entrypoint.sh"]
