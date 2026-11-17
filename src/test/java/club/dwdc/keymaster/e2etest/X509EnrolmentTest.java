package club.dwdc.keymaster.e2etest;

import club.dwdc.keymaster.daemon.DaemonController;
import club.dwdc.keymaster.daemon.DaemonServer;
import club.dwdc.keymaster.desktop.FileIdentityStore;
import club.dwdc.keyvault.core.SeedStore;
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
import org.testcontainers.utility.MountableFile;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Mission 37.1.5: Alice enrolled by an external CA, end to end.
 *
 * <p>Runs keymaster-avatar's {@code doc/x509-enrolment.sh} (the runbook's single
 * source, {@code -Dx509.enrolment.script}) step by step inside the avatar
 * container, against a real in-process KeyMaster:
 * <ul>
 *   <li>the token signs Alice's CSR;</li>
 *   <li>an openssl test CA issues the certificate;</li>
 *   <li>the certificate is deposited on the token;</li>
 *   <li>a gnutls client-auth handshake uses it, with a negative control.</li>
 * </ul>
 * It also covers the rejections (wrong EKU, foreign key) and renewal. Every
 * step is asserted on its exit code and on the script's {@code ok}/{@code FAIL}
 * lines.
 *
 * <p>Its own class, with its own relay, avatar and KeyMaster store, so "the token
 * had no certificate before" holds: {@code KeyMasterAvatarTest} test 81 imports
 * a certificate. The setup and helpers are a minimal copy of
 * {@code KeyMasterAvatarTest}'s; that class is deliberately left as it is.
 *
 * <p>No private key is committed: the test CA key, the server key and the
 * foreign key are generated in the container at run time.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@Timeout(value = 3, unit = TimeUnit.MINUTES)
class X509EnrolmentTest {

    private static final Logger log = LoggerFactory.getLogger(X509EnrolmentTest.class);

    // ---- copied from KeyMasterAvatarTest: binaries and identity ----

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

    // ---- in the avatar container ----

    private static final String X509_SA_SOCK = "/tmp/keymaster-x509-sa.sock";
    private static final String SCRIPT = "/opt/x509-enrolment/x509-enrolment.sh";
    private static final String WORKDIR = "/tmp/x509-enrolment";
    private static final String P11_TOKEN = "pkcs11:token=KeyMaster%20X.509";
    private static final String P11_KIT_PROXY = "/usr/lib/x86_64-linux-gnu/p11-kit-proxy.so";
    /** The script's default PORT=4433, as /proc/net/tcp writes it (hex). */
    private static final String PORT_HEX = ":1151";
    private static final List<String> FIXTURES = List.of(
            "alice.tmpl", "client.ext", "server.ext", "client-serverauth.ext", "client-clientauth-email.ext");

    private static final String X509_LIST = rpc(1, "list", new JsonObject());

    @TempDir
    static Path kvHome;

    private static DaemonServer daemonServer;
    private static DaemonController daemonController;
    private static Network network;

    @SuppressWarnings("resource")
    private static GenericContainer<?> relay;

    @SuppressWarnings("resource")
    private static GenericContainer<?> avatar;

    private static String avatarLoginXpub;

    @BeforeAll
    static void startContainers() throws Exception {
        // Both inputs are required: fail loudly, never skip.
        if (PKCS11_X509_MODULE == null || !Files.isRegularFile(Path.of(PKCS11_X509_MODULE))) {
            throw new IllegalStateException("-Dpkcs11.x509.module must name libkm_pkcs11_x509.so, got: "
                    + PKCS11_X509_MODULE);
        }
        if (X509_ENROLMENT_SCRIPT == null || !Files.isRegularFile(Path.of(X509_ENROLMENT_SCRIPT))) {
            throw new IllegalStateException(
                    "-Dx509.enrolment.script must name keymaster-avatar/doc/x509-enrolment.sh, got: "
                    + X509_ENROLMENT_SCRIPT);
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
        ImageFromDockerfile avatarImage = new ImageFromDockerfile()
                .withFileFromPath("Dockerfile", Path.of("docker/avatar/Dockerfile"))
                .withFileFromPath("keymaster-avatar", Path.of(AVATAR_BINARY))
                .withFileFromPath("km-ssh-sa", Path.of(SSH_AVATAR_BINARY))
                .withFileFromPath("km-gpg-sa", Path.of(GPG_AVATAR_BINARY))
                .withFileFromPath("km-nostr-sa", Path.of(NOSTR_AVATAR_BINARY))
                .withFileFromPath("km-x509-sa", Path.of(X509_AVATAR_BINARY))
                .withFileFromPath("libkm_pkcs11_x509.so", Path.of(PKCS11_X509_MODULE))
                .withFileFromPath("scd-shim", Path.of(SCD_SHIM_BINARY))
                .withFileFromPath("entrypoint.sh", Path.of("docker/avatar/entrypoint.sh"));

        avatar = new GenericContainer<>(avatarImage)
                .withCommand("--relay", "ws://relay:7777", "--log-level", "debug")
                .withNetwork(network)
                .dependsOn(relay)
                .withEnv("SSH_AUTH_SOCK", "/tmp/keymaster-avatar-ssh-agent.sock")
                .withEnv("GNUPGHOME", "/tmp/gnupg-home")
                .withLogConsumer(new Slf4jLogConsumer(log).withPrefix("avatar"))
                .waitingFor(Wait.forLogMessage(".*Local API listening.*", 1));
        avatar.start();

        Matcher m = Pattern.compile("Login xpub:\\s*(xpub[A-Za-z0-9]+)").matcher(avatar.getLogs());
        if (!m.find()) {
            throw new IllegalStateException("Could not find login xpub in logs:\n" + avatar.getLogs());
        }
        avatarLoginXpub = m.group(1);
        log.info("Avatar login xpub: {}", avatarLoginXpub);

        // Everything the script needs, so a gap in the image fails here, by name.
        p11Ok("bash", "-c", "command -v bash stdbuf timeout awk sed grep seq sha256sum "
                + "gnutls-serv gnutls-cli certtool p11tool pkcs11-tool openssl"
                + " && test -e " + P11_KIT_PROXY + " && test -r /proc/net/tcp");

        // The script and the committed fixtures; the script's defaults then apply.
        p11Ok("mkdir", "-p", WORKDIR);
        avatar.copyFileToContainer(MountableFile.forHostPath(Path.of(X509_ENROLMENT_SCRIPT), 0755), SCRIPT);
        for (String fixture : FIXTURES) {
            avatar.copyFileToContainer(
                    MountableFile.forClasspathResource("x509/" + fixture), WORKDIR + "/" + fixture);
        }

        // One session for the whole enrolment, as in real use.
        attachViaController(writeDescriptor("descriptor-x509-enrolment.json", "x509").toString(),
                "alice@atlanta.com", "auto");
        JsonObject key = onlyX509Key(awaitX509Result(X509_LIST, 20_000));
        assertFalse(key.has("cert"), "fresh KeyMaster store, no certificate: " + key);
    }

    // ==================== the enrolment, step by step ====================

    @Test
    @Order(10)
    void makeTestPki() throws Exception {
        assertStep(step("make_test_pki"), 0,
                "ok   make_test_pki: test CA and server certificate (server.pem, CN=localhost) made;"
                + " server certificate verifies");
    }

    @Test
    @Order(20)
    void tokenHasNoCertificateBefore() throws Exception {
        assertTokenHasNoCert();
    }

    @Test
    @Order(30)
    void selectKey() throws Exception {
        String listId = HexFormat.of().formatHex(base64Field(listKey(), "id"));
        String okPrefix = "ok   select_key: exactly one tls-client key pair; shared CKA_ID (SHA-256 of the SPKI) ";
        var r = assertStep(step("select_key"), 0, "select_key: private key: ", "select_key: public key:  ", okPrefix);

        for (String type : List.of("private", "public")) {
            String url = line(r, "select_key: " + type + " key:");
            assertTrue(url.contains("type=" + type) && url.contains("id=")
                    && url.contains("object=alice%40atlanta.com%20tls-client"), url + "\n" + out(r));
        }
        assertEquals(listId, line(r, okPrefix).substring(okPrefix.length()).trim(),
                "the token's CKA_ID == the id from km-x509-sa list\n" + out(r));
    }

    @Test
    @Order(40)
    void makeCsr() throws Exception {
        listKey();
        assertStep(step("make_csr"), 0,
                "ok   make_csr: CSR self-signature verifies",
                "ok   make_csr: CSR SPKI sha256 == token CKA_ID");
    }

    @Test
    @Order(50)
    void caIssue() throws Exception {
        var r = assertStep(step("ca_issue"), 0, "ok   ca_issue: alice.crt written");
        assertTrue(r.getStdout().contains("TLS Web Client Authentication")
                && !r.getStdout().contains("TLS Web Server Authentication")
                && !r.getStdout().contains("E-mail Protection"),
                "the CA's TLS-client profile: EKU clientAuth only\n" + out(r));
    }

    @Test
    @Order(60)
    void verifyChain() throws Exception {
        listKey();
        assertStep(step("verify_chain"), 0,
                "ok   verify_chain: openssl verify: alice.crt: OK",
                "ok   verify_chain: certtool --verify-chain: Verified. The certificate is trusted.",
                "ok   verify_chain: certificate SPKI sha256 == token CKA_ID");
    }

    @Test
    @Order(70)
    void wrongEkuServerAuthRejected() throws Exception {
        assertWrongEkuRejected("client-serverauth", "TLS Web Server Authentication");
    }

    @Test
    @Order(71)
    void wrongEkuClientAuthEmailRejected() throws Exception {
        assertWrongEkuRejected("client-clientauth-email", "TLS Web Client Authentication, E-mail Protection");
    }

    @Test
    @Order(80)
    void depositGood() throws Exception {
        JsonObject before = listKey();
        String id = HexFormat.ofDelimiter(":").formatHex(base64Field(before, "id"));
        assertStep(step("deposit"), 0,
                "ok   deposit: certificate SPKI sha256 == token CKA_ID: certificate and key pair",
                "ok   deposit: token lists 3 objects (private key, public key, certificate), one shared ID",
                "ok   deposit: exactly one certificate on the token");

        // Independently of the script
        var all = p11Ok("p11tool", "--batch", "--list-all", P11_TOKEN);
        assertEquals(3, objectCount(all), out(all));
        assertEquals(List.of(id, id, id), p11Ids(all.getStdout()), "one shared CKA_ID\n" + out(all));
        assertEquals(fileFingerprint("alice.crt"), tokenCertFingerprint(), "the token holds alice.crt");
        assertArrayEquals(der("alice.der"), base64Field(listKey(), "cert"),
                "km-x509-sa list returns the deposited certificate");
    }

    @Test
    @Order(90)
    void foreignKeyRejected() throws Exception {
        listKey();
        // A key that is not Alice's, with a certificate from the same test CA and profile.
        inWorkdir("umask 077"
                + " && openssl ecparam -name prime256v1 -genkey -noout -out foreign.key"
                + " && openssl req -new -key foreign.key -subj /CN=alice@atlanta.com -out foreign.csr"
                + " && openssl x509 -req -in foreign.csr -CA test-ca.pem -CAkey test-ca.key -CAcreateserial"
                + " -extfile client.ext -days 7 -out foreign.crt");

        var r = assertStep(step("deposit", "CERT_FILE=foreign.crt"), 1,
                "FAIL deposit: pkcs11-tool --write-object refused foreign.der");
        assertTrue(line(r, "FAIL deposit:").endsWith("certificate SPKI sha256 == token CKA_ID: no"),
                "the key does not match\n" + out(r));
        assertTrue(out(r).contains("CKR_ATTRIBUTE_VALUE_INVALID"), "refused by C_CreateObject\n" + out(r));

        // Unchanged: still exactly the good certificate, on the token and in KeyMaster
        var all = p11Ok("p11tool", "--batch", "--list-all", P11_TOKEN);
        assertEquals(3, objectCount(all), out(all));
        assertEquals(fileFingerprint("alice.crt"), tokenCertFingerprint(), "the token still holds alice.crt");
        assertArrayEquals(der("alice.der"), base64Field(listKey(), "cert"),
                "km-x509-sa list still returns alice.crt");
    }

    @Test
    @Order(100)
    void handshake() throws Exception {
        listKey();
        try {
            assertStep(step("handshake"), 0,
                    "ok   handshake: client sent 1 certificate",
                    "ok   handshake: HTTP/1.0 200 OK, and the server's page shows the peer CN=alice@atlanta.com",
                    "ok   handshake: server verified the client's ECDSA-SECP256R1-SHA256 signature"
                    + " (made by the token)");
        } finally {
            assertPortFree();
        }
    }

    @Test
    @Order(110)
    void handshakeWithoutCertRefused() throws Exception {
        try {
            var r = assertStep(step("handshake_without_cert"), 0,
                    "ok   handshake_without_cert: refused: exit ",
                    "ok   handshake_without_cert: server log: Certificate is required");
            assertTrue(line(r, "ok   handshake_without_cert: refused:").endsWith(", alert 116, no page"), out(r));
            var serverLog = p11Ok("cat", WORKDIR + "/server-nocert.log");
            assertTrue(serverLog.getStdout().contains("Error in handshake: Certificate is required."),
                    "gnutls-serv refused the client\n" + out(serverLog));
        } finally {
            assertPortFree();
        }
    }

    @Test
    @Order(120)
    void renewalReplacesCertificate() throws Exception {
        listKey();
        assertStep(step("ca_issue", "CERT_FILE=alice2.crt"), 0, "ok   ca_issue: alice2.crt written");
        assertStep(step("deposit", "CERT_FILE=alice2.crt"), 0,
                "ok   deposit: certificate SPKI sha256 == token CKA_ID: certificate and key pair",
                "ok   deposit: token lists 3 objects (private key, public key, certificate), one shared ID",
                "ok   deposit: exactly one certificate on the token");

        assertNotEquals(fileFingerprint("alice.crt"), fileFingerprint("alice2.crt"), "a new certificate");
        assertEquals(fileFingerprint("alice2.crt"), tokenCertFingerprint(), "the token holds the new certificate");
        byte[] stored = base64Field(listKey(), "cert");
        assertArrayEquals(der("alice2.der"), stored, "km-x509-sa list returns the new certificate");
    }

    // ==================== script and token helpers ====================

    /** Run one step of the enrolment script in the avatar container; {@code extraEnv} as NAME=value. */
    private static ExecResult step(String name, String... extraEnv) throws Exception {
        List<String> command = new ArrayList<>();
        command.add("WORKDIR=" + WORKDIR);
        command.addAll(List.of(extraEnv));
        // timeout: on a hang the script gets TERM, exits, and its EXIT trap stops gnutls-serv.
        command.addAll(List.of("timeout", "120", SCRIPT, name));
        return p11(command.toArray(String[]::new));
    }

    /** Exit code and the script's expected lines (by prefix); every failure shows the full output. */
    private static ExecResult assertStep(ExecResult r, int expectedExit, String... linePrefixes) {
        String output = "x509-enrolment.sh output:\n" + out(r);
        assertEquals(expectedExit, r.getExitCode(), "exit code\n" + output);
        for (String prefix : linePrefixes) {
            assertNotNull(line(r, prefix), "no line starting '" + prefix + "'\n" + output);
        }
        return r;
    }

    /** The first stdout line starting with {@code prefix}, or null. */
    private static String line(ExecResult r, String prefix) {
        return r.getStdout().lines().filter(l -> l.startsWith(prefix)).findFirst().orElse(null);
    }

    /** CA issues {@code <profile>.crt} with {@code <profile>.ext}; deposit refuses it; token and list unchanged. */
    private static void assertWrongEkuRejected(String profile, String ekuPrintout) throws Exception {
        String crt = profile + ".crt";
        var issued = assertStep(step("ca_issue", "CLIENT_EXT=" + profile + ".ext", "CERT_FILE=" + crt), 0,
                "ok   ca_issue: " + crt + " written");
        assertTrue(issued.getStdout().contains(ekuPrintout),
                "the certificate really carries the wrong EKU\n" + out(issued));

        var r = assertStep(step("deposit", "CERT_FILE=" + crt), 1,
                "FAIL deposit: pkcs11-tool --write-object refused " + profile + ".der");
        assertTrue(line(r, "FAIL deposit:").endsWith("certificate SPKI sha256 == token CKA_ID: yes"),
                "Alice's key, so the EKU is what is refused\n" + out(r));
        assertTrue(out(r).contains("CKR_ATTRIBUTE_VALUE_INVALID"), "refused by C_CreateObject\n" + out(r));

        assertTokenHasNoCert();
    }

    /** check_no_cert passes and KeyMaster's list has no certificate. */
    private static void assertTokenHasNoCert() throws Exception {
        JsonObject key = listKey();
        assertFalse(key.has("cert"), "KeyMaster holds no certificate: " + key);
        assertStep(step("check_no_cert"), 0, "ok   check_no_cert: no certificate on the token");
    }

    /** Nothing listens on TCP 4433 (hex 1151) in the avatar container: no LISTEN (0A) row in /proc/net/tcp{,6}. */
    private static void assertPortFree() throws Exception {
        var r = p11("awk", "FNR > 1 && $4 == \"0A\" && substr($2, length($2) - 4) == \"" + PORT_HEX + "\""
                + " { print FILENAME \": \" $0 }", "/proc/net/tcp", "/proc/net/tcp6");
        assertEquals("", r.getStdout().trim(), "port 4433 still listening (gnutls-serv left running?)\n" + out(r));
    }

    /** Alice's one key from km-x509-sa list, once the session answers. */
    private static JsonObject listKey() throws Exception {
        return onlyX509Key(awaitX509Result(X509_LIST, 20_000));
    }

    /** SHA-256 fingerprint of the token's one certificate, as openssl prints it. */
    private static String tokenCertFingerprint() throws Exception {
        var urls = p11Ok("p11tool", "--batch", "--list-all-certs", "--only-urls", P11_TOKEN);
        List<String> lines = urls.getStdout().lines().map(String::trim).filter(l -> !l.isEmpty()).toList();
        assertEquals(1, lines.size(), "exactly one certificate on the token\n" + out(urls));
        return p11Ok("bash", "-c", "p11tool --batch --export \"$1\" | openssl x509 -noout -fingerprint -sha256",
                "_", lines.get(0)).getStdout().trim();
    }

    private static String fileFingerprint(String crt) throws Exception {
        return p11Ok("openssl", "x509", "-in", WORKDIR + "/" + crt, "-noout", "-fingerprint", "-sha256")
                .getStdout().trim();
    }

    /** A DER file the script wrote in WORKDIR. */
    private static byte[] der(String file) throws Exception {
        return Base64.getDecoder().decode(p11Ok("base64", "-w0", WORKDIR + "/" + file).getStdout().trim());
    }

    private static void inWorkdir(String script) throws Exception {
        p11Ok("bash", "-c", "cd " + WORKDIR + " && " + script);
    }

    // ==================== copied from KeyMasterAvatarTest ====================

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
                "command failed: " + String.join(" ", command) + "\n" + out(result));
        return result;
    }

    /** Exit code, stdout and stderr, for assertion messages. */
    private static String out(ExecResult r) {
        return "exit=" + r.getExitCode() + "\n--- stdout ---\n" + r.getStdout() + "--- stderr ---\n" + r.getStderr();
    }

    private static int objectCount(ExecResult r) {
        return (int) r.getStdout().lines().filter(l -> l.startsWith("Object")).count();
    }

    /** The "ID:" values p11tool prints, in order. */
    private static List<String> p11Ids(String listing) {
        return listing.lines().map(String::trim).filter(l -> l.startsWith("ID:"))
                .map(l -> l.substring(3).trim()).toList();
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

    private static byte[] base64Field(JsonObject object, String field) {
        assertTrue(object.has(field), "missing '" + field + "': " + object);
        return Base64.getDecoder().decode(object.get(field).getAsString());
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

    @AfterAll
    static void tearDown() {
        if (daemonController != null) detachViaController();
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
