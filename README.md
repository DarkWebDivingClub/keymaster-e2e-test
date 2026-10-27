# club.dwdc.keymaster.e2etest

End-to-end tests for KeyMaster. This is the **mandatory gate**: every
mission that touches the Java stack has to show this suite green before
it can be called done.

The tests run a real strfry relay and a real `keymaster-avatar` in
Testcontainers, embed `km-daemon` in-process, and drive it over its
JSON-RPC socket — attaching identities, then exercising SSH and GPG
signing end to end against the live agents.

## Prerequisites

- **JDK 21**, set explicitly. JDK 25 is the default `java` on current
  Ubuntu and the build targets 21.
- Maven 3.9+
- **Docker**, running and usable by the current user.

```sh
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
```

The suite resolves `keymaster` and `keyvault` from `~/.m2`, so build
those first — see the build order in
[keymaster's README](https://github.com/DarkWebDivingClub/keymaster#build).
The versions it builds against are pinned in `pom.xml`:

```xml
<keymaster.version>0.7.3</keymaster.version>
<keyvault.version>0.4.0</keyvault.version>
```

Bump those pins when a new keymaster or keyvault is released, or this
suite silently keeps testing an older one.

## Run

```sh
mvn test
```

Expect `Tests run: 20` from `KeyMasterAvatarTest` and a build that takes
roughly four minutes, most of it spent building container images.

### The LXC system test

`KeyMasterSystemTest` is **excluded from `mvn test` by design** — it
needs LXC with unprivileged container support. It is gated behind a
profile:

```sh
mvn test -Psystem-test
```

## Troubleshooting

**Image build fails on `apt-get update` (exit code 100), or Maven hangs
fetching `maven-metadata.xml`.** Not a test failure. On a machine behind
the h3 VPN this is the MTU blackhole: `tun0` comes up at 1500 over a
1500-MTU underlay, so bulk transfer stalls while handshakes succeed.
Docker needs its own MTU — the host setting does not reach containers:

```sh
echo '{"mtu": 1360}' | sudo tee /etc/docker/daemon.json
sudo systemctl restart docker    # this stops every running container
```

Confirm with `docker run --rm debian:bookworm-slim apt-get update`.

**`ERROR DaemonController - Attach failed: realm ... already has a
connector`** in a passing run is expected. It is asserted deliberately
by `oneRealmTwoConnectors_sameRelay`.

## License

GNU General Public License v3.0 only (`GPL-3.0-only`).
