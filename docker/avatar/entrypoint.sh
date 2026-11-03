#!/bin/bash
set -e
export GNUPGHOME=/tmp/gnupg-home
mkdir -p "$GNUPGHOME"
chmod 700 "$GNUPGHOME"

# Start keymaster-avatar in background
keymaster-avatar "$@" &
AVATAR_PID=$!

# Wait for local API socket to appear
TIMEOUT=20
ELAPSED=0
while [ ! -S /tmp/keymaster-avatar.sock ] && [ "$ELAPSED" -lt "$TIMEOUT" ]; do
    sleep 0.5
    ELAPSED=$((ELAPSED + 1))
done

if [ ! -S /tmp/keymaster-avatar.sock ]; then
    echo "ERROR: local API socket not created within ${TIMEOUT}s" >&2
    kill $AVATAR_PID 2>/dev/null
    exit 1
fi

# Start service avatars with auto-restart (like systemd Restart=on-failure).
# "|| true" prevents set -e (inherited by subshell) from killing the loop
# when an SA exits non-zero (e.g. km-gpg-sa before a session is established).
(while true; do km-ssh-sa --log-level debug || true; sleep 1; done) &
(while true; do km-gpg-sa --log-level debug || true; sleep 1; done) &
(while true; do km-nostr-sa --log-level debug || true; sleep 1; done) &
# km-x509-sa has no /tmp fallback for its client socket and XDG_RUNTIME_DIR is
# unset here, so --listen-socket is required; the tests talk to this path.
(while true; do km-x509-sa --avatar-socket /tmp/keymaster-avatar.sock \
    --listen-socket /tmp/keymaster-x509-sa.sock --log-level debug || true; sleep 1; done) &

echo "Avatar PID=$AVATAR_PID, SAs started"

# Wait for avatar to exit
wait $AVATAR_PID
