package club.dwdc.keymaster.e2etest;

import club.dwdc.keymaster.daemon.DaemonController;
import club.dwdc.keymaster.daemon.DaemonServer;
import club.dwdc.keymaster.desktop.FileIdentityStore;
import club.dwdc.keyvault.core.SeedStore;
import com.github.dockerjava.api.model.Capability;
import com.github.dockerjava.api.model.Device;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.Container.ExecResult;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.images.builder.Transferable;
import org.testcontainers.utility.MountableFile;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Mission 37.1.8: OpenVPN with a token-held key, end to end.
 *
 * <p>Alice is enrolled with 37.1.5's {@code doc/x509-enrolment.sh}
 * ({@code -Dx509.enrolment.script}), then keymaster-avatar's
 * {@code doc/x509-openvpn.sh} ({@code -Dx509.openvpn.script}, the runbook's
 * single source) runs step by step in the avatar container:
 * <ul>
 *   <li>the OpenSSL gate: openssl s_client through pkcs11-provider with key and
 *       certificate from the token, plus a negative control without a
 *       certificate;</li>
 *   <li>{@code openvpn --show-pkcs11-ids} lists exactly Alice's certificate;</li>
 *   <li>a client config with pkcs11-providers + pkcs11-id and no cert/key.</li>
 * </ul>
 * The script leaves starting OpenVPN to its environment; here that is two
 * containers from the same image on the test network: the avatar container
 * (holds the token) is the VPN client, a second container ({@code vpnserver},
 * no keymaster-avatar) runs only the OpenVPN server with the software server
 * key. The tunnel must come up, carry traffic, survive a reconnect (SIGUSR1)
 * and a renegotiation, and refuse a client certificate from another CA.
 *
 * <p>Token cost: km-x509-sa logs every forwarded request ({@code [x509] sign (}
 * / {@code [x509] list (}) via tracing to stdout; entrypoint.sh starts it with
 * the container's stdout, so the lines are in the avatar container's Docker
 * logs. The test prints the deltas per event as {@code TOKEN <event> ...}.
 *
 * <p>Its own class with its own relay, avatar and KeyMaster store; the setup
 * and helpers are a minimal copy of {@code X509EnrolmentTest}'s, which is left
 * as it is. No private key is committed: the test CA, server and "other CA"
 * keys are generated in the containers at run time and never reach the host
 * disk.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@Timeout(value = 3, unit = TimeUnit.MINUTES)
class X509OpenVpnTest {

    private static final Logger log = LoggerFactory.getLogger(X509OpenVpnTest.class);

    // ---- copied from X509EnrolmentTest: binaries and identity ----

    static final String TEST_MNEMONIC =
            "abandon abandon abandon abandon abandon abandon " +
            "abandon abandon abandon abandon abandon about";

    private static final String AVATAR_BINARY = System.getProperty(
            "avatar.binary", "/home/rene/git/keymaster-avatar/target/release/keymaster-avatar");
    private static final String SSH_AVATAR_BINARY = System.getProperty(
            "ssh.avatar.binary", "/home/rene/git/keymaster-avatar/target/release/km-ssh-sa");
    private static final String GPG_AVATAR_BINARY = System.getProperty(
            "gpg.avatar.binary", "/home/rene/git/keymaster-avatar/target/release/km-gpg-sa");
    private static final String NOSTR_AVATAR_BINARY = System.getProperty(
            "nostr.avatar.binary", "/home/rene/git/keymaster-avatar/target/release/km-nostr-sa");
    private static final String X509_AVATAR_BINARY = System.getProperty(
            "x509.avatar.binary", "/home/rene/git/keymaster-avatar/target/release/km-x509-sa");
    private static final String SCD_SHIM_BINARY = System.getProperty(
            "scd.shim.binary", "/home/rene/git/keymaster-avatar/target/release/scd-shim");

    /** Required, no default: -Dpkcs11.x509.module=<path to libkm_pkcs11_x509.so>. */
    private static final String PKCS11_X509_MODULE = System.getProperty("pkcs11.x509.module");

    /** Required, no default: -Dx509.enrolment.script=<keymaster-avatar/doc/x509-enrolment.sh>. */
    private static final String X509_ENROLMENT_SCRIPT = System.getProperty("x509.enrolment.script");

    /** Required, no default: -Dx509.openvpn.script=<keymaster-avatar/doc/x509-openvpn.sh>. */
    private static final String X509_OPENVPN_SCRIPT = System.getProperty("x509.openvpn.script");

    // ---- in the containers ----

    private static final String X509_SA_SOCK = "/tmp/keymaster-x509-sa.sock";
    private static final String ENROLMENT = "/opt/x509-enrolment/x509-enrolment.sh";
    private static final String OPENVPN = "/opt/x509-openvpn/x509-openvpn.sh";
    /** Shared by both scripts: x509-openvpn.sh reuses test-ca.pem, server.pem/key and alice.crt. */
    private static final String WORKDIR = "/tmp/x509-enrolment";
    /** In the server container. */
    private static final String SERVER_DIR = "/tmp/openvpn-server";
    private static final String SERVER_ALIAS = "vpnserver";
    private static final String P11_KIT_PROXY = "/usr/lib/x86_64-linux-gnu/p11-kit-proxy.so";
    private static final String OSSL_PKCS11 = "/usr/lib/x86_64-linux-gnu/ossl-modules/pkcs11.so";
    private static final String VPN_DEV = "tunkm0";
    private static final String PEER_TUN = "10.99.0.1";
    private static final String ALICE_CN = "CN=alice@atlanta.com";
    private static final String MALLORY_CN = "CN=mallory@example.test";
    /** The client process itself, not a wrapper (spec 5.5: never pkill -f). */
    private static final String CLIENT_PATTERN = "^openvpn --config alice-test.ovpn";
    private static final String MALLORY_PATTERN = "^openvpn --config mallory-test.ovpn";
    private static final String ISC = "Initialization Sequence Completed";
    private static final String ALICE_VERIFIED = "VERIFY OK: depth=0, " + ALICE_CN;
    private static final List<String> FIXTURES = List.of(
            "alice.tmpl", "client.ext", "server.ext", "client-serverauth.ext", "client-clientauth-email.ext");

    private static final String X509_LIST = rpc(1, "list", new JsonObject());
    private static final Pattern TOKEN_SIGN = Pattern.compile("\\[x509\\] sign \\(");
    private static final Pattern TOKEN_LIST = Pattern.compile("\\[x509\\] list \\(");

    @TempDir
    static Path kvHome;

    private static DaemonServer daemonServer;
    private static DaemonController daemonController;
    private static Network network;

    @SuppressWarnings("resource")
    private static GenericContainer<?> relay;

    /** The VPN client: holds the token. */
    @SuppressWarnings("resource")
    private static GenericContainer<?> avatar;

    /** The VPN server: same image, no keymaster-avatar, software server key. */
    @SuppressWarnings("resource")
    private static GenericContainer<?> vpnserver;

    private static String avatarLoginXpub;

    @BeforeAll
    static void startContainers() throws Exception {
        // All inputs are required: fail loudly, never skip.
        if (PKCS11_X509_MODULE == null || !Files.isRegularFile(Path.of(PKCS11_X509_MODULE))) {
            throw new IllegalStateException("-Dpkcs11.x509.module must name libkm_pkcs11_x509.so, got: "
                    + PKCS11_X509_MODULE);
        }
        if (X509_ENROLMENT_SCRIPT == null || !Files.isRegularFile(Path.of(X509_ENROLMENT_SCRIPT))) {
            throw new IllegalStateException(
                    "-Dx509.enrolment.script must name keymaster-avatar/doc/x509-enrolment.sh, got: "
                    + X509_ENROLMENT_SCRIPT);
        }
        if (X509_OPENVPN_SCRIPT == null || !Files.isRegularFile(Path.of(X509_OPENVPN_SCRIPT))) {
            throw new IllegalStateException(
                    "-Dx509.openvpn.script must name keymaster-avatar/doc/x509-openvpn.sh, got: "
                    + X509_OPENVPN_SCRIPT);
        }

        // Embedded km-daemon with a fresh store (this class's own @TempDir)
        Path socketPath = kvHome.resolve("keymaster.sock");
        FileIdentityStore identityStore = new FileIdentityStore(kvHome);
        daemonController = new DaemonController(new StubSeedStore(), identityStore, kvHome);
        daemonServer = new DaemonServer(socketPath, daemonController);
        daemonServer.start();
        log.info("Embedded km-daemon started on {}", socketPath);

        JsonObject createParams = new JsonObject();
        createParams.addProperty("identity", "alice@atlanta.com");
        createParams.addProperty("pgp_name", "Alice");
        createParams.addProperty("pgp_email", "alice@atlanta.com");
        JsonObject createResult = daemonController.handle("identity.create", createParams);
        assertFalse(createResult.has("error"), "identity.create failed: " + createResult);

        network = Network.newNetwork();

        relay = new GenericContainer<>("dockurr/strfry:1.0.4")
                .withExposedPorts(7777)
                .withNetwork(network)
                .withNetworkAliases("relay")
                .withTmpFs(Map.of("/app/strfry-db", "rw"))
                .withCopyFileToContainer(
                        MountableFile.forClasspathResource("strfry.conf"), "/etc/strfry.conf")
                .waitingFor(Wait.forListeningPort());
        relay.start();
        log.info("Relay started on port {}", relay.getMappedPort(7777));

        // The image's Dockerfile COPYs every binary, so all of them are passed.
        // One instance for both containers, so the image is built once.
        ImageFromDockerfile image = new ImageFromDockerfile()
                .withFileFromPath("Dockerfile", Path.of("docker/avatar/Dockerfile"))
                .withFileFromPath("keymaster-avatar", Path.of(AVATAR_BINARY))
                .withFileFromPath("km-ssh-sa", Path.of(SSH_AVATAR_BINARY))
                .withFileFromPath("km-gpg-sa", Path.of(GPG_AVATAR_BINARY))
                .withFileFromPath("km-nostr-sa", Path.of(NOSTR_AVATAR_BINARY))
                .withFileFromPath("km-x509-sa", Path.of(X509_AVATAR_BINARY))
                .withFileFromPath("libkm_pkcs11_x509.so", Path.of(PKCS11_X509_MODULE))
                .withFileFromPath("scd-shim", Path.of(SCD_SHIM_BINARY))
                .withFileFromPath("entrypoint.sh", Path.of("docker/avatar/entrypoint.sh"));

        // Both OpenVPN ends create tunkm0: NET_ADMIN and /dev/net/tun. Commands
        // run as root (the image has no USER), as openvpn needs.
        avatar = new GenericContainer<>(image)
                .withCommand("--relay", "ws://relay:7777", "--log-level", "debug")
                .withNetwork(network)
                .dependsOn(relay)
                .withEnv("SSH_AUTH_SOCK", "/tmp/keymaster-avatar-ssh-agent.sock")
                .withEnv("GNUPGHOME", "/tmp/gnupg-home")
                .withCreateContainerCmdModifier(cmd -> cmd.getHostConfig()
                        .withCapAdd(Capability.NET_ADMIN)
                        .withDevices(new Device("rwm", "/dev/net/tun", "/dev/net/tun")))
                .withLogConsumer(new Slf4jLogConsumer(log).withPrefix("avatar"))
                .waitingFor(Wait.forLogMessage(".*Local API listening.*", 1));
        avatar.start();

        // The entrypoint (not just the command) is replaced: entrypoint.sh
        // would pass the command to keymaster-avatar.
        vpnserver = new GenericContainer<>(image)
                .withNetwork(network)
                .withNetworkAliases(SERVER_ALIAS)
                .withCreateContainerCmdModifier(cmd -> {
                    cmd.withEntrypoint("sleep", "infinity");
                    cmd.getHostConfig()
                            .withCapAdd(Capability.NET_ADMIN)
                            .withDevices(new Device("rwm", "/dev/net/tun", "/dev/net/tun"));
                })
                .withLogConsumer(new Slf4jLogConsumer(log).withPrefix("vpnserver"));
        vpnserver.start();

        Matcher m = Pattern.compile("Login xpub:\\s*(xpub[A-Za-z0-9]+)").matcher(avatar.getLogs());
        if (!m.find()) {
            throw new IllegalStateException("Could not find login xpub in logs:\n" + avatar.getLogs());
        }
        avatarLoginXpub = m.group(1);
        log.info("Avatar login xpub: {}", avatarLoginXpub);

        // Everything both scripts and the test need, so a gap in the image fails here, by name.
        p11Ok("bash", "-c", "command -v bash stdbuf timeout awk sed grep seq sha256sum pgrep "
                + "gnutls-serv gnutls-cli certtool p11tool pkcs11-tool openssl openvpn ip ping"
                + " && test -e " + P11_KIT_PROXY + " && test -e " + OSSL_PKCS11 + " && test -r /proc/net/tcp");
        srvOk("bash", "-c", "command -v openvpn pgrep");
        // openvpn --version exits non-zero on some versions; head decides the status.
        log.info("TOOLS openvpn (client): {}",
                p11Ok("bash", "-c", "openvpn --version | head -n 1").getStdout().trim());
        log.info("TOOLS openvpn (server): {}",
                srvOk("bash", "-c", "openvpn --version | head -n 1").getStdout().trim());

        // The scripts and the committed fixtures; the scripts' defaults then apply.
        p11Ok("mkdir", "-p", WORKDIR);
        avatar.copyFileToContainer(MountableFile.forHostPath(Path.of(X509_ENROLMENT_SCRIPT), 0755), ENROLMENT);
        avatar.copyFileToContainer(MountableFile.forHostPath(Path.of(X509_OPENVPN_SCRIPT), 0755), OPENVPN);
        for (String fixture : FIXTURES) {
            avatar.copyFileToContainer(
                    MountableFile.forClasspathResource("x509/" + fixture), WORKDIR + "/" + fixture);
        }

        // One session for the whole class, as in real use.
        attachViaController(writeDescriptor("descriptor-x509-openvpn.json", "x509").toString(),
                "alice@atlanta.com", "auto");
        JsonObject key = onlyX509Key(awaitX509Result(X509_LIST, 20_000));
        assertFalse(key.has("cert"), "fresh KeyMaster store, no certificate: " + key);

        // Prerequisite (37.1.5), not a DoD line: a failure here aborts the class.
        assertStep(step(ENROLMENT, "make_test_pki"), 0, "ok   make_test_pki:");
        assertStep(step(ENROLMENT, null), 0, "== all checks passed:");
        log.info("Alice enrolled (x509-enrolment.sh make_test_pki + all steps)");
    }

    // ==================== the OpenSSL gate ====================

    @Test
    @Order(10)
    void opensslGate() throws Exception {
        Token before = tokenCounts();
        var conf = assertStep(step(OPENVPN, "provider_conf"), 0, "ok   provider_conf: providers active: ");
        log.info("TOOLS {}", line(conf, "ok   provider_conf: providers active: ").substring(5));
        assertStep(step(OPENVPN, "openssl_gate"), 0,
                "ok   openssl_gate: exit 0, Protocol: TLSv1.3",
                "ok   openssl_gate: the server's page shows a Client certificate section with " + ALICE_CN,
                "ok   openssl_gate: s_server log: depth=0 " + ALICE_CN);
        Token d = tokenDelta("openssl-gate", before, 1, 0);
        assertTrue(d.sign >= 1, () -> "the gate's handshake signed with the token: " + d + vpnLogs());
    }

    @Test
    @Order(20)
    void opensslGateWithoutCertRefused() throws Exception {
        Token before = tokenCounts();
        var r = assertStep(step(OPENVPN, "openssl_gate_without_cert"), 0,
                "ok   openssl_gate_without_cert: refused: exit ",
                "ok   openssl_gate_without_cert: s_server log: peer did not return a certificate");
        assertTrue(line(r, "ok   openssl_gate_without_cert: refused:")
                .endsWith(", alert 116 (certificate required), no page"), () -> diag(r));
        Token d = tokenDelta("openssl-gate-without-cert", before, 0, 0);
        assertEquals(0, d.sign, () -> "no certificate, no token signature: " + d + diag(r));
    }

    // ==================== OpenVPN ====================

    @Test
    @Order(30)
    void showIdsListsAlice() throws Exception {
        Token before = tokenCounts();
        var r = assertStep(step(OPENVPN, "show_ids"), 0,
                "ok   show_ids: exactly one Certificate, DN " + ALICE_CN,
                "ok   show_ids: pkcs11-id written: token DWDC/KeyMaster/0000000000000001/",
                "show_ids: pkcs11-id: ");
        assertTrue(line(r, "ok   show_ids: pkcs11-id written:").endsWith("CKA_ID == the key's"), () -> diag(r));

        // Independently of the script
        var ids = p11Ok("cat", WORKDIR + "/show-pkcs11-ids.txt");
        List<String> lines = ids.getStdout().lines().map(String::trim).toList();
        assertEquals(1, lines.stream().filter("Certificate"::equals).count(),
                () -> "exactly one certificate listed\n" + diag(ids));
        assertEquals(List.of("DN: " + ALICE_CN),
                lines.stream().filter(l -> l.startsWith("DN:")).map(l -> l.replaceAll("\\s+", " ")).toList(),
                () -> "exactly Alice's certificate\n" + diag(ids));

        Token d = tokenDelta("show-ids", before, 0, 1);
        assertEquals(0, d.sign, () -> "listing needs no signature: " + d + diag(r));
        assertTrue(d.list >= 1, () -> "listing asks the token: " + d + diag(r));
    }

    @Test
    @Order(40)
    void writeConfigsWithoutCertOrKey() throws Exception {
        var r = assertStep(step(OPENVPN, "write_configs", "SERVER_ADDR=" + SERVER_ALIAS, "LOCAL_ADDR="), 0,
                "write_configs: server.ovpn written (no 'local': all addresses",
                "write_configs: alice-test.ovpn written (remote " + SERVER_ALIAS + " 1195",
                "ok   write_configs: alice-test.ovpn has no cert, key or pkcs12 line",
                "ok   write_configs: exactly one pkcs11-id line, equal to pkcs11-id (backslashes intact)");

        // Independently of the script
        var client = p11Ok("cat", WORKDIR + "/alice-test.ovpn");
        List<String> cl = client.getStdout().lines().map(String::trim).toList();
        assertTrue(cl.contains("pkcs11-providers " + P11_KIT_PROXY), () -> diag(client));
        assertEquals(1, cl.stream().filter(l -> l.startsWith("pkcs11-id ")).count(), () -> diag(client));
        assertTrue(cl.contains("remote " + SERVER_ALIAS + " 1195"), () -> diag(client));
        assertTrue(cl.stream().noneMatch(l -> l.matches("(cert|key|pkcs12)(\\s.*)?")),
                () -> "no cert, key or pkcs12 in the client config\n" + diag(client));
        var server = p11Ok("cat", WORKDIR + "/server.ovpn");
        assertTrue(server.getStdout().lines().noneMatch(l -> l.startsWith("local ")),
                () -> "LOCAL_ADDR= : no 'local' line\n" + diag(server));

        // The server's files, container to container, in memory only.
        srvOk("mkdir", "-p", SERVER_DIR);
        for (String f : List.of("test-ca.pem", "server.pem", "server.key", "server.ovpn")) {
            byte[] bytes = avatar.copyFileFromContainer(WORKDIR + "/" + f, InputStream::readAllBytes);
            vpnserver.copyFileToContainer(Transferable.of(bytes, f.endsWith(".key") ? 0600 : 0644),
                    SERVER_DIR + "/" + f);
        }
        srvOk("test", "-s", SERVER_DIR + "/server.key");
    }

    @Test
    @Order(50)
    void tunnelUpWithPkcs11Id() throws Exception {
        var s = srv("bash", "-c", "cd " + SERVER_DIR + " && setsid openvpn --config server.ovpn --log server.log"
                + " </dev/null >/dev/null 2>&1 &");
        assertEquals(0, s.getExitCode(), () -> "server start\n" + diag(s));
        waitForCount(vpnserver, SERVER_DIR + "/server.log", "link local", 1, 30_000);

        Token before = tokenCounts();
        long t0 = System.nanoTime();
        startClient("client.log");
        waitForCount(avatar, WORKDIR + "/client.log", ISC, 1, 60_000);
        long ms = (System.nanoTime() - t0) / 1_000_000;
        waitForCount(vpnserver, SERVER_DIR + "/server.log", ISC, 1, 30_000);
        assertTrue(count(vpnserver, SERVER_DIR + "/server.log", ALICE_VERIFIED) >= 1,
                () -> "the server verified Alice's certificate\n" + vpnLogs());
        log.info("TIMING first-connect start->ISC={} ms (polled every 250 ms)", ms);

        Token d = tokenDelta("first-connect", before, 1, 0);
        assertTrue(d.sign >= 1, () -> "the handshake signed with the token: " + d + vpnLogs());

        // DCO or tun: observed, not forced.
        String c = datapath(avatar, WORKDIR + "/client.log");
        String sv = datapath(vpnserver, SERVER_DIR + "/server.log");
        log.info("DATAPATH client: {}", c);
        log.info("DATAPATH server: {}", sv);
        assertTrue(c.contains("opened") && sv.contains("opened"),
                () -> "no 'device ... opened' line\n" + vpnLogs());
    }

    @Test
    @Order(60)
    void tunnelCarriesTraffic() throws Exception {
        assertTunnel();
    }

    @Test
    @Order(70)
    void reconnectSurvives() throws Exception {
        int verified = count(vpnserver, SERVER_DIR + "/server.log", ALICE_VERIFIED);
        String pid = clientPid();
        Token before = tokenCounts();
        long t0 = System.nanoTime();
        p11Ok("kill", "-USR1", pid);
        waitForCount(avatar, WORKDIR + "/client.log", ISC, 2, 60_000);
        long ms = (System.nanoTime() - t0) / 1_000_000;
        assertTrue(count(avatar, WORKDIR + "/client.log", "SIGUSR1[hard,] received") >= 1,
                () -> "SIGUSR1 restart in the client log\n" + vpnLogs());
        assertEquals(pid, clientPid(), () -> "a restart in the same process\n" + vpnLogs());
        waitForCount(vpnserver, SERVER_DIR + "/server.log", ALICE_VERIFIED, verified + 1, 30_000);
        log.info("TIMING reconnect signal->ISC={} ms (polled every 250 ms)", ms);

        Token d = tokenDelta("reconnect", before, 1, 0);
        assertTrue(d.sign >= 1, () -> "the new handshake signed with the token: " + d + vpnLogs());
        assertTunnel();
    }

    @Test
    @Order(75)
    void renegotiation() throws Exception {
        try {
            stopClient();
            startClient("client-reneg.log", "--reneg-sec", "15");
            waitForCount(avatar, WORKDIR + "/client-reneg.log", ISC, 1, 60_000);
            // After the new process's first connect, so its list is not counted.
            int verified = count(vpnserver, SERVER_DIR + "/server.log", ALICE_VERIFIED);
            Token before = tokenCounts();
            long t0 = System.nanoTime();
            waitForCount(avatar, WORKDIR + "/client-reneg.log", "soft reset", 1, 45_000);
            long ms = (System.nanoTime() - t0) / 1_000_000;
            waitForCount(vpnserver, SERVER_DIR + "/server.log", ALICE_VERIFIED, verified + 1, 30_000);
            log.info("TIMING renegotiation ISC->soft reset={} ms (reneg-sec 15)", ms);

            Token d = tokenDelta("renegotiation", before, 1, 0);
            assertTrue(d.sign >= 1, () -> "the renegotiation signed with the token: " + d + vpnLogs());
            assertEquals(0, d.list, () -> "no list for a renegotiation: " + d + vpnLogs());
            assertTunnel();
        } finally {
            stopClient();
        }
    }

    @Test
    @Order(80)
    void otherCaRefused() throws Exception {
        try {
            stopClient();  // the tun device must be free (spec 5.7 TUNSETIFF)

            inWorkdir("umask 077"
                    + " && openssl ecparam -name prime256v1 -genkey -noout -out other-ca.key"
                    + " && openssl req -x509 -new -key other-ca.key -subj '/CN=Other CA 37.1.8' -days 7"
                    + " -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign"
                    + " -out other-ca.pem"
                    + " && openssl ecparam -name prime256v1 -genkey -noout -out mallory.key"
                    + " && openssl req -new -key mallory.key -subj /CN=mallory@example.test -out mallory.csr"
                    + " && openssl x509 -req -in mallory.csr -CA other-ca.pem -CAkey other-ca.key -CAcreateserial"
                    + " -extfile client.ext -days 7 -out mallory.crt"
                    + " && grep -v '^pkcs11-' alice-test.ovpn > mallory-test.ovpn"
                    + " && printf 'cert mallory.crt\\nkey mallory.key\\n' >> mallory-test.ovpn");

            int refused = countRegex(vpnserver, SERVER_DIR + "/server.log", "VERIFY ERROR.*" + MALLORY_CN);
            Token before = tokenCounts();
            // The client retries forever; timeout signals openvpn directly.
            var r = p11("bash", "-c", "cd " + WORKDIR
                    + " && timeout 20 openvpn --config mallory-test.ovpn --log mallory.log");
            assertEquals(124, r.getExitCode(), () -> "killed by timeout, never connected\n" + diag(r));
            assertEquals(0, count(avatar, WORKDIR + "/mallory.log", ISC),
                    () -> "no tunnel for the other CA's certificate\n" + diag(r));
            waitForCountRegex(vpnserver, SERVER_DIR + "/server.log", "VERIFY ERROR.*" + MALLORY_CN,
                    refused + 1, 5_000);

            Token d = tokenDelta("other-ca", before, 0, 0);
            assertEquals(0, d.sign, () -> "a software key: token untouched: " + d + diag(r));
        } finally {
            killMatching(MALLORY_PATTERN);
        }
    }

    // ==================== OpenVPN helpers ====================

    /** The OpenVPN client in the background, in WORKDIR, X509_SA_SOCK passed through. */
    private static void startClient(String logFile, String... extraArgs) throws Exception {
        String extra = extraArgs.length == 0 ? "" : " " + String.join(" ", extraArgs);
        var r = p11("bash", "-c", "cd " + WORKDIR + " && setsid openvpn --config alice-test.ovpn --log "
                + logFile + extra + " </dev/null >/dev/null 2>&1 &");
        assertEquals(0, r.getExitCode(), () -> "client start\n" + diag(r));
    }

    /** The pid of the one OpenVPN client process (the process itself, not a wrapper). */
    private static String clientPid() throws Exception {
        var r = p11("pgrep", "-f", CLIENT_PATTERN);
        List<String> pids = r.getStdout().lines().map(String::trim).filter(l -> !l.isEmpty()).toList();
        assertEquals(1, pids.size(), () -> "exactly one OpenVPN client process\n" + diag(r));
        return pids.get(0);
    }

    /** Stops the OpenVPN client, if running, and waits until the process and tunkm0 are gone. */
    private static void stopClient() throws Exception {
        killMatching(CLIENT_PATTERN);
        long deadline = System.currentTimeMillis() + 20_000;
        while (true) {
            boolean running = p11("pgrep", "-f", CLIENT_PATTERN).getExitCode() == 0;
            boolean device = p11("ip", "link", "show", VPN_DEV).getExitCode() == 0;
            if (!running && !device) return;
            if (System.currentTimeMillis() >= deadline) {
                fail("OpenVPN client or " + VPN_DEV + " still there 20 s after SIGTERM\n" + vpnLogs());
            }
            Thread.sleep(250);
        }
    }

    /** SIGTERM to each process whose command line matches (pgrep, never pkill -f). */
    private static void killMatching(String pattern) throws Exception {
        var r = p11("pgrep", "-f", pattern);
        for (String pid : r.getStdout().lines().map(String::trim).filter(l -> !l.isEmpty()).toList()) {
            p11("kill", "-TERM", pid);
        }
    }

    /** tunnel_check: route via tunkm0 and ping 3/3. */
    private static void assertTunnel() throws Exception {
        assertStep(step(OPENVPN, "tunnel_check"), 0,
                "ok   tunnel_check: route to " + PEER_TUN + ": dev " + VPN_DEV,
                "ok   tunnel_check: ping " + PEER_TUN + ": 3/3 through the tunnel");
    }

    /** The log's "device ... opened" line(s) and any DCO note. */
    private static String datapath(GenericContainer<?> c, String file) throws Exception {
        var r = c.execInContainer("grep", "-E", "device .*opened|data channel offload|DCO", file);
        String lines = r.getStdout().lines().map(String::trim).reduce((a, b) -> a + " | " + b).orElse("");
        return lines.isEmpty() ? "(no device line)" : lines;
    }

    private static int count(GenericContainer<?> c, String file, String text) throws Exception {
        return grepCount(c, "-cF", text, file);
    }

    private static int countRegex(GenericContainer<?> c, String file, String regex) throws Exception {
        return grepCount(c, "-cE", regex, file);
    }

    /** grep -c; a missing file counts 0. */
    private static int grepCount(GenericContainer<?> c, String flags, String pattern, String file) throws Exception {
        var r = c.execInContainer("grep", flags, "--", pattern, file);
        try {
            return Integer.parseInt(r.getStdout().trim());
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static void waitForCount(GenericContainer<?> c, String file, String text, int n, long timeoutMs)
            throws Exception {
        awaitCount(() -> count(c, file, text), file, "'" + text + "'", n, timeoutMs);
    }

    private static void waitForCountRegex(GenericContainer<?> c, String file, String regex, int n, long timeoutMs)
            throws Exception {
        awaitCount(() -> countRegex(c, file, regex), file, "/" + regex + "/", n, timeoutMs);
    }

    private interface Counter {
        int get() throws Exception;
    }

    /** Polls every 250 ms until the count reaches n; at the deadline fails with both OpenVPN logs. */
    private static void awaitCount(Counter counter, String file, String what, int n, long timeoutMs)
            throws Exception {
        long deadline = System.currentTimeMillis() + timeoutMs;
        int got;
        while ((got = counter.get()) < n) {
            if (System.currentTimeMillis() >= deadline) {
                fail("expected " + n + "x " + what + " in " + file + " within " + timeoutMs + " ms, got "
                        + got + "\n" + vpnLogs());
            }
            Thread.sleep(250);
        }
    }

    /** All OpenVPN logs of both sides, for assertion messages. */
    private static String vpnLogs() {
        StringBuilder sb = new StringBuilder();
        for (String f : List.of("client.log", "client-reneg.log", "mallory.log")) {
            sb.append(catLog(avatar, "client " + f, WORKDIR + "/" + f));
        }
        sb.append(catLog(vpnserver, "server server.log", SERVER_DIR + "/server.log"));
        return sb.toString();
    }

    private static String catLog(GenericContainer<?> c, String name, String file) {
        try {
            var r = c.execInContainer("bash", "-c", "cat \"$1\" 2>/dev/null || echo '(no file)'", "_", file);
            return "\n--- " + name + " ---\n" + r.getStdout();
        } catch (Exception e) {
            return "\n--- " + name + ": " + e + "\n";
        }
    }

    /** Command output plus both OpenVPN logs. */
    private static String diag(ExecResult r) {
        return out(r) + vpnLogs();
    }

    // ==================== token interactions ====================

    private record Token(int sign, int list) {
        Token minus(Token o) {
            return new Token(sign - o.sign, list - o.list);
        }

        @Override
        public String toString() {
            return "sign=" + sign + " list=" + list;
        }
    }

    /** km-x509-sa's forwarded sign/list requests so far, from the avatar container's Docker logs. */
    private static Token tokenCounts() {
        String logs = avatar.getLogs();
        return new Token((int) TOKEN_SIGN.matcher(logs).results().count(),
                (int) TOKEN_LIST.matcher(logs).results().count());
    }

    /**
     * The delta since {@code before}, logged as {@code TOKEN <event> ...}. The
     * Docker log stream can lag, so it polls up to 5 s until the minimums are
     * reached; with no minimum it reads after 1 s.
     */
    private static Token tokenDelta(String event, Token before, int minSign, int minList) throws Exception {
        boolean expectSome = minSign > 0 || minList > 0;
        long deadline = System.currentTimeMillis() + (expectSome ? 5_000 : 1_000);
        Token now;
        Token d;
        while (true) {
            now = tokenCounts();
            d = now.minus(before);
            if (expectSome && d.sign >= minSign && d.list >= minList) break;
            if (System.currentTimeMillis() >= deadline) break;
            Thread.sleep(250);
        }
        log.info("TOKEN {} {} (total {})", event, d, now);
        return d;
    }

    // ==================== script helpers ====================

    /** Run one step of a script in the avatar container (null: all steps); {@code extraEnv} as NAME=value. */
    private static ExecResult step(String script, String name, String... extraEnv) throws Exception {
        List<String> command = new ArrayList<>();
        command.add("WORKDIR=" + WORKDIR);
        command.addAll(List.of(extraEnv));
        // timeout: on a hang the script gets TERM, exits, and its EXIT trap stops its server.
        command.addAll(List.of("timeout", name == null ? "300" : "120", script));
        if (name != null) command.add(name);
        return p11(command.toArray(String[]::new));
    }

    /** Exit code and the script's expected lines (by prefix); every failure shows the output and the OpenVPN logs. */
    private static ExecResult assertStep(ExecResult r, int expectedExit, String... linePrefixes) {
        Supplier<String> output = () -> "script output:\n" + diag(r);
        assertEquals(expectedExit, r.getExitCode(), () -> "exit code\n" + output.get());
        for (String prefix : linePrefixes) {
            assertNotNull(line(r, prefix), () -> "no line starting '" + prefix + "'\n" + output.get());
        }
        return r;
    }

    /** The first stdout line starting with {@code prefix}, or null. */
    private static String line(ExecResult r, String prefix) {
        return r.getStdout().lines().filter(l -> l.startsWith(prefix)).findFirst().orElse(null);
    }

    private static void inWorkdir(String script) throws Exception {
        p11Ok("bash", "-c", "cd " + WORKDIR + " && " + script);
    }

    // ==================== copied from X509EnrolmentTest ====================

    /** Run a command in the avatar container, pointed at the e2e km-x509-sa socket. */
    private static ExecResult p11(String... command) throws Exception {
        String[] full = new String[command.length + 2];
        full[0] = "env";
        full[1] = "X509_SA_SOCK=" + X509_SA_SOCK;
        System.arraycopy(command, 0, full, 2, command.length);
        var result = avatar.execInContainer(full);
        log.info("$ {}\n{}", String.join(" ", command), out(result));
        return result;
    }

    /** Same, and the command must exit 0; the message carries its output. */
    private static ExecResult p11Ok(String... command) throws Exception {
        var result = p11(command);
        assertEquals(0, result.getExitCode(),
                () -> "command failed: " + String.join(" ", command) + "\n" + out(result));
        return result;
    }

    /** Run a command in the server container. */
    private static ExecResult srv(String... command) throws Exception {
        var result = vpnserver.execInContainer(command);
        log.info("[vpnserver] $ {}\n{}", String.join(" ", command), out(result));
        return result;
    }

    private static ExecResult srvOk(String... command) throws Exception {
        var result = srv(command);
        assertEquals(0, result.getExitCode(),
                () -> "command failed in vpnserver: " + String.join(" ", command) + "\n" + out(result));
        return result;
    }

    /** Exit code, stdout and stderr, for assertion messages. */
    private static String out(ExecResult r) {
        return "exit=" + r.getExitCode() + "\n--- stdout ---\n" + r.getStdout() + "--- stderr ---\n" + r.getStderr();
    }

    /** A JSON-RPC 2.0 request line. */
    private static String rpc(int id, String method, JsonObject params) {
        JsonObject request = new JsonObject();
        request.addProperty("jsonrpc", "2.0");
        request.addProperty("id", id);
        request.addProperty("method", method);
        request.add("params", params);
        return request.toString();
    }

    /** The single key in a list result; fails if there isn't exactly one. */
    private static JsonObject onlyX509Key(JsonObject listResponse) {
        JsonArray keys = listResponse.getAsJsonObject("result").getAsJsonArray("keys");
        assertEquals(1, keys.size(), "exactly Alice's TLS-client key: " + listResponse);
        return keys.get(0).getAsJsonObject();
    }

    /**
     * Send one request to km-x509-sa, retrying every 500 ms until the reply
     * has a result.
     */
    private static JsonObject awaitX509Result(String request, long timeoutMs) throws Exception {
        long deadline = System.currentTimeMillis() + timeoutMs;
        String last = "no attempt";
        while (true) {
            try {
                JsonObject response = x509Sa(request);
                if (response.has("result")) {
                    return response;
                }
                last = response.toString();
            } catch (RuntimeException e) {
                last = e.getMessage();
            }
            if (System.currentTimeMillis() >= deadline) {
                fail("km-x509-sa gave no result within " + timeoutMs + " ms; last: " + last);
            }
            Thread.sleep(500);
        }
    }

    private static JsonObject x509Sa(String request) throws Exception {
        return lineRpc(avatar, X509_SA_SOCK, request).get(0);
    }

    /** Newline-delimited JSON-RPC over one unix-socket connection in the container. */
    private static List<JsonObject> lineRpc(GenericContainer<?> container, String socketPath,
            String... requests) throws Exception {
        String script = String.join("\n",
                "import socket,sys",
                "s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)",
                "s.settimeout(40)",
                "s.connect(sys.argv[1])",
                "f=s.makefile('rwb')",
                "for req in sys.argv[2:]:",
                "  f.write(req.encode()+b'\\n')",
                "  f.flush()",
                "  line=f.readline()",
                "  if not line: raise Exception('EOF')",
                "  print(line.decode().strip())",
                "s.close()");
        String[] command = new String[4 + requests.length];
        command[0] = "python3";
        command[1] = "-c";
        command[2] = script;
        command[3] = socketPath;
        System.arraycopy(requests, 0, command, 4, requests.length);

        var result = container.execInContainer(command);
        if (result.getExitCode() != 0) {
            throw new RuntimeException("request to " + socketPath + " failed (exit="
                    + result.getExitCode() + "): " + result.getStderr());
        }
        List<JsonObject> replies = result.getStdout().lines()
                .filter(line -> !line.isBlank())
                .map(line -> JsonParser.parseString(line).getAsJsonObject())
                .toList();
        if (replies.size() != requests.length) {
            throw new RuntimeException("expected " + requests.length + " replies, got: " + result.getStdout());
        }
        return replies;
    }

    private static Path writeDescriptor(String filename, String service) throws Exception {
        String relayUrl = "ws://" + relay.getHost() + ":" + relay.getMappedPort(7777);
        String descriptorJson = String.format(
                "{\"relay\":\"%s\",\"login_xpub\":\"%s\",\"services\":[\"%s\"]}",
                relayUrl, avatarLoginXpub, service);
        Path file = kvHome.resolve(filename);
        Files.writeString(file, descriptorJson);
        return file;
    }

    private static void attachViaController(String descriptorPath, String identity, String policy) {
        JsonObject params = new JsonObject();
        params.addProperty("descriptor", descriptorPath);
        params.addProperty("identity", identity);
        if (policy != null) params.addProperty("policy", policy);
        JsonObject result = daemonController.handle("session.attach", params);
        assertFalse(result.has("error"), "session.attach failed: " + result);
    }

    private static void detachViaController() {
        daemonController.handle("session.detach", new JsonObject());
    }

    /** Stops every openvpn (by exact process name) in a container; errors ignored. */
    private static void stopOpenVpn(GenericContainer<?> c) {
        if (c == null || !c.isRunning()) return;
        try {
            c.execInContainer("bash", "-c", "for p in $(pgrep -x openvpn); do kill \"$p\"; done; true");
        } catch (Exception e) {
            log.warn("stopping openvpn failed: {}", e.toString());
        }
    }

    @AfterAll
    static void tearDown() {
        if (avatar != null && avatar.isRunning()) log.info("TOKEN total {}", tokenCounts());
        stopOpenVpn(avatar);
        stopOpenVpn(vpnserver);
        if (daemonController != null) detachViaController();
        if (vpnserver != null) vpnserver.stop();
        if (avatar != null) avatar.stop();
        if (relay != null) relay.stop();
        if (network != null) network.close();
        if (daemonServer != null) daemonServer.stop();
    }

    private static class StubSeedStore implements SeedStore {
        @Override public boolean exists() { return true; }
        @Override public void store(String m, String p) {}
        @Override public String getMnemonic() { return TEST_MNEMONIC; }
        @Override public String getPassphrase() { return ""; }
        @Override public void delete() {}
    }
}
