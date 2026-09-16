package club.dwdc.keymaster.e2etest;

import club.dwdc.keymaster.SshServiceHandler;
import club.dwdc.keymaster.daemon.DaemonController;
import club.dwdc.keymaster.daemon.DaemonServer;
import club.dwdc.keymaster.desktop.FileIdentityStore;
import club.dwdc.keyvault.core.Bip32KeyVault;
import club.dwdc.keyvault.core.KeyVault;
import club.dwdc.keyvault.core.SeedStore;
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
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.utility.MountableFile;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import nostr.crypto.nip44.EncryptedPayloads;
import nostr.util.NostrUtil;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.math.ec.ECPoint;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

/**
 * E2E test: KeyMaster daemon/client with Avatar over a Nostr relay.
 *
 * <p>Uses Testcontainers to automatically start a strfry relay and keymaster-avatar
 * in Docker. Runs km-daemon in-process via embedded DaemonController/DaemonServer.
 *
 * <p>Typical run time: ~70 seconds. The 2-minute class-level timeout ensures
 * the suite never hangs indefinitely.
 *
 * <p>Run with: {@code mvn test}
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@Timeout(value = 3, unit = TimeUnit.MINUTES)
class KeyMasterAvatarTest {

    private static final Logger log = LoggerFactory.getLogger(KeyMasterAvatarTest.class);

    static final String TEST_MNEMONIC =
            "abandon abandon abandon abandon abandon abandon " +
            "abandon abandon abandon abandon abandon about";

    private static final String AVATAR_BINARY = System.getProperty(
            "avatar.binary",
            "/home/rene/git/keymaster-avatar/target/release/keymaster-avatar");

    private static final String SSH_AVATAR_BINARY = System.getProperty(
            "ssh.avatar.binary",
            "/home/rene/git/keymaster-avatar/target/release/km-ssh-sa");

    private static final String GPG_AVATAR_BINARY = System.getProperty(
            "gpg.avatar.binary",
            "/home/rene/git/keymaster-avatar/target/release/km-gpg-sa");

    private static final String NOSTR_AVATAR_BINARY = System.getProperty(
            "nostr.avatar.binary",
            "/home/rene/git/keymaster-avatar/target/release/km-nostr-sa");

    private static final String SCD_SHIM_BINARY = System.getProperty(
            "scd.shim.binary",
            "/home/rene/git/keymaster-avatar/target/release/scd-shim");

    @TempDir
    static Path kvHome;

    private static Path socketPath;
    private static DaemonServer daemonServer;
    private static DaemonController daemonController;
    private static Network network;

    @SuppressWarnings("resource")
    private static GenericContainer<?> relay;

    @SuppressWarnings("resource")
    private static GenericContainer<?> avatar;

    @SuppressWarnings("resource")
    private static GenericContainer<?> sshd;

    /** Second avatar container with "packaged" layout: binaries off PATH, config-driven. */
    @SuppressWarnings("resource")
    private static GenericContainer<?> avatarPackaged;

    private static String avatarLoginXpub;
    private static String avatarPackagedLoginXpub;

    @BeforeAll
    static void startContainers() throws Exception {
        // Register BouncyCastle for ChaCha20 (needed by NIP-44 local crypto)
        if (Security.getProvider("BC") == null) {
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
        }

        // Embedded km-daemon — no subprocesses needed
        socketPath = kvHome.resolve("keymaster.sock");
        SeedStore seedStore = new StubSeedStore();
        FileIdentityStore identityStore = new FileIdentityStore(kvHome);
        daemonController = new DaemonController(seedStore, identityStore, kvHome);
        daemonServer = new DaemonServer(socketPath, daemonController);
        daemonServer.start();
        log.info("Embedded km-daemon started on {}", socketPath);

        // Create identity via direct controller call
        JsonObject createParams = new JsonObject();
        createParams.addProperty("identity", "alice@atlanta.com");
        createParams.addProperty("pgp_name", "Alice");
        createParams.addProperty("pgp_email", "alice@atlanta.com");
        JsonObject createResult = daemonController.handle("identity.create", createParams);
        assertFalse(createResult.has("error"),
                "identity.create failed: " + createResult);
        log.info("Identity created: {}", createResult.get("pubkey").getAsString());

        network = Network.newNetwork();

        // Start strfry relay
        relay = new GenericContainer<>("dockurr/strfry:1.0.4")
                .withExposedPorts(7777)
                .withNetwork(network)
                .withNetworkAliases("relay")
                .withTmpFs(Map.of("/app/strfry-db", "rw"))
                .withCopyFileToContainer(
                        MountableFile.forClasspathResource("strfry.conf"),
                        "/etc/strfry.conf")
                .waitingFor(Wait.forListeningPort());
        relay.start();
        log.info("Relay started on port {}", relay.getMappedPort(7777));

        // Build sshd target container — derive SSH authorized_keys from vault
        KeyVault vaultForKeys = createVaultInProcess();
        String authorizedKeys = SshServiceHandler.getAuthorizedKeysLine(
                vaultForKeys, "alice@atlanta.com");
        log.info("Authorized keys: {}", authorizedKeys);

        ImageFromDockerfile sshdImage = new ImageFromDockerfile()
                .withFileFromPath("Dockerfile", Path.of("docker/sshd/Dockerfile"))
                .withFileFromString("authorized_keys", authorizedKeys + "\n");

        sshd = new GenericContainer<>(sshdImage)
                .withExposedPorts(22)
                .withNetwork(network)
                .withNetworkAliases("sshd-target")
                .withLogConsumer(new Slf4jLogConsumer(log).withPrefix("sshd"))
                .waitingFor(Wait.forListeningPort());
        sshd.start();
        log.info("SSHD container started on port {}", sshd.getMappedPort(22));

        // Build avatar image
        ImageFromDockerfile avatarImage = new ImageFromDockerfile()
                .withFileFromPath("Dockerfile", Path.of("docker/avatar/Dockerfile"))
                .withFileFromPath("keymaster-avatar", Path.of(AVATAR_BINARY))
                .withFileFromPath("km-ssh-sa", Path.of(SSH_AVATAR_BINARY))
                .withFileFromPath("km-gpg-sa", Path.of(GPG_AVATAR_BINARY))
                .withFileFromPath("km-nostr-sa", Path.of(NOSTR_AVATAR_BINARY))
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
        log.info("Avatar container started");

        // Parse avatar login_xpub from container logs
        String logs = avatar.getLogs();
        Matcher m = Pattern.compile("Login xpub:\\s*(xpub[A-Za-z0-9]+)").matcher(logs);
        if (!m.find()) {
            throw new IllegalStateException(
                    "Could not find login xpub in logs:\n" + logs);
        }
        avatarLoginXpub = m.group(1);
        log.info("Avatar login xpub: {}", avatarLoginXpub);

        // Build "packaged layout" avatar: binaries off PATH, config-driven SA lookup
        String avatarToml = "service_avatar_dir = \"/usr/lib/keymaster-avatar\"\n";

        ImageFromDockerfile packagedImage = new ImageFromDockerfile()
                .withFileFromPath("Dockerfile", Path.of("docker/avatar/Dockerfile.packaged"))
                .withFileFromPath("keymaster-avatar", Path.of(AVATAR_BINARY))
                .withFileFromPath("km-ssh-sa", Path.of(SSH_AVATAR_BINARY))
                .withFileFromPath("km-gpg-sa", Path.of(GPG_AVATAR_BINARY))
                .withFileFromPath("km-nostr-sa", Path.of(NOSTR_AVATAR_BINARY))
                .withFileFromPath("scd-shim", Path.of(SCD_SHIM_BINARY))
                .withFileFromPath("entrypoint-packaged.sh", Path.of("docker/avatar/entrypoint-packaged.sh"))
                .withFileFromString("avatar.toml", avatarToml);

        avatarPackaged = new GenericContainer<>(packagedImage)
                .withCommand("--relay", "ws://relay:7777", "--log-level", "debug")
                .withNetwork(network)
                .dependsOn(relay)
                .withEnv("SSH_AUTH_SOCK", "/tmp/keymaster-avatar-ssh-agent.sock")
                .withEnv("GNUPGHOME", "/tmp/gnupg-home")
                .withLogConsumer(new Slf4jLogConsumer(log).withPrefix("avatar-pkg"))
                .waitingFor(Wait.forLogMessage(".*Local API listening.*", 1));
        avatarPackaged.start();
        log.info("Packaged avatar container started");

        String pkgLogs = avatarPackaged.getLogs();
        Matcher mp = Pattern.compile("Login xpub:\\s*(xpub[A-Za-z0-9]+)").matcher(pkgLogs);
        if (!mp.find()) {
            throw new IllegalStateException(
                    "Could not find login xpub in packaged avatar logs:\n" + pkgLogs);
        }
        avatarPackagedLoginXpub = mp.group(1);
        log.info("Packaged avatar login xpub: {}", avatarPackagedLoginXpub);
    }

    @Test
    @Order(1)
    void statusShowsNotAttached() {
        JsonObject result = daemonController.handle("session.status", new JsonObject());
        assertFalse(result.has("error"), "status should not have error: " + result);
        assertFalse(result.get("attached").getAsBoolean());
    }

    @Test
    @Order(2)
    void noServiceSpawnInLogs() {
        String logs = avatar.getLogs();
        assertFalse(logs.contains("service.spawn"),
                "Avatar logs should not contain 'service.spawn' — channels are derived from xpubs");
    }

    @Test
    @Order(10)
    void attachViaCliAndSshAddWorks() throws Exception {
        Path descriptorFile = writeDescriptor("descriptor-ssh.json", "ssh");

        attachViaController(descriptorFile.toString(), "alice@atlanta.com", "auto");

        try {
            Thread.sleep(2000);

            // Verify SSH agent socket was created by km-ssh-sa
            var socketResult = avatar.execInContainer("test", "-S",
                    "/tmp/keymaster-avatar-ssh-agent.sock");
            assertEquals(0, socketResult.getExitCode(),
                    "SSH agent socket should exist after attach. stderr: " + socketResult.getStderr());

            // Run ssh-add -l inside the avatar container
            var result = avatar.execInContainer("ssh-add", "-l");
            log.info("ssh-add exit code: {}, stdout: {}, stderr: {}",
                    result.getExitCode(), result.getStdout(), result.getStderr());
            assertNotEquals(2, result.getExitCode(),
                    "ssh-add should reach the agent. stderr: " + result.getStderr());
        } finally {
            detachViaController();
            Thread.sleep(500);
        }
    }

    @Test
    @Order(20)
    void sshLoginToRemoteHost() throws Exception {
        Path descriptorFile = writeDescriptor("descriptor-ssh-login.json", "ssh");

        attachViaController(descriptorFile.toString(), "alice@atlanta.com", "auto");

        try {
            Thread.sleep(2000);

            // Verify key is available
            var listResult = avatar.execInContainer("ssh-add", "-l");
            log.info("ssh-add -l exit={}, stdout={}, stderr={}",
                    listResult.getExitCode(), listResult.getStdout(), listResult.getStderr());
            assertEquals(0, listResult.getExitCode(),
                    "ssh-add -l should list keys. stderr: " + listResult.getStderr());

            // SSH login to the sshd target
            var sshResult = avatar.execInContainer(
                    "ssh",
                    "-o", "StrictHostKeyChecking=no",
                    "-o", "UserKnownHostsFile=/dev/null",
                    "-o", "BatchMode=yes",
                    "testuser@sshd-target",
                    "echo", "hello-from-keymaster");

            log.info("ssh exit={}, stdout={}, stderr={}",
                    sshResult.getExitCode(), sshResult.getStdout(), sshResult.getStderr());
            assertEquals(0, sshResult.getExitCode(),
                    "SSH login should succeed. stderr: " + sshResult.getStderr());
            assertTrue(sshResult.getStdout().contains("hello-from-keymaster"),
                    "SSH output should contain 'hello-from-keymaster'. stdout: " + sshResult.getStdout());
        } finally {
            detachViaController();
            Thread.sleep(500);
        }
    }

    @Test
    @Order(30)
    void gpgSignAndVerify() throws Exception {
        Path descriptorFile = writeDescriptor("descriptor-gpg.json", "gpg");

        attachViaController(descriptorFile.toString(), "alice@atlanta.com", "auto");

        try {
            // Wait for km-gpg-sa to complete GPG setup (LEARN, import, ownertrust, stubs).
            // The direct controller attach call completes ~3s faster than the old subprocess,
            // so km-gpg-sa needs more wall-clock time after attach to finish setup.
            Thread.sleep(12000);

            // Sign a test message
            avatar.execInContainer("bash", "-c", "echo 'test message' > /tmp/test.txt");

            var signResult = avatar.execInContainer(
                    "gpg", "--homedir", "/tmp/gnupg-home",
                    "--batch", "--yes", "--clearsign",
                    "--pinentry-mode", "loopback", "--passphrase", "",
                    "/tmp/test.txt");
            log.info("GPG sign: exit={}, stdout={}, stderr={}",
                    signResult.getExitCode(), signResult.getStdout(), signResult.getStderr());

            assertEquals(0, signResult.getExitCode(),
                    "GPG clearsign should succeed. stderr: " + signResult.getStderr());

            // Verify the signature
            var verifyResult = avatar.execInContainer(
                    "gpg", "--homedir", "/tmp/gnupg-home",
                    "--batch", "--verify", "/tmp/test.txt.asc");
            log.info("GPG verify: exit={}, stdout={}, stderr={}",
                    verifyResult.getExitCode(), verifyResult.getStdout(), verifyResult.getStderr());
            assertEquals(0, verifyResult.getExitCode(),
                    "GPG verify should succeed. stderr: " + verifyResult.getStderr());
        } finally {
            detachViaController();
            Thread.sleep(500);
        }
    }

    @Test
    @Order(40)
    void serviceProcessRespawnsOnCrash() throws Exception {
        Path descriptorFile = writeDescriptor("descriptor-respawn.json", "ssh");

        attachViaController(descriptorFile.toString(), "alice@atlanta.com", "auto");

        try {
            Thread.sleep(2000);

            // Verify SSH agent is working
            var result1 = avatar.execInContainer("ssh-add", "-l");
            assertEquals(0, result1.getExitCode(),
                    "ssh-add should work before kill. stderr: " + result1.getStderr());

            // Kill km-ssh-sa
            var killResult = avatar.execInContainer("pkill", "km-ssh-sa");
            log.info("pkill exit={}, stdout={}, stderr={}",
                    killResult.getExitCode(), killResult.getStdout(), killResult.getStderr());

            // Wait for respawn — the entrypoint restart loop needs time to relaunch km-ssh-sa
            // and the new process needs to reconnect to the avatar's local API.
            Thread.sleep(5000);

            // Verify SSH agent works again
            var result2 = avatar.execInContainer("ssh-add", "-l");
            log.info("ssh-add after respawn: exit={}, stdout={}, stderr={}",
                    result2.getExitCode(), result2.getStdout(), result2.getStderr());
            assertEquals(0, result2.getExitCode(),
                    "ssh-add should work after respawn. stderr: " + result2.getStderr());
        } finally {
            detachViaController();
        }
    }

    // ==================== Nostr service avatar tests ====================

    @Test
    @Order(33)
    void nostrGetPublicKeys() throws Exception {
        Path descriptorFile = writeDescriptor("descriptor-nostr-keys.json", "nostr");

        attachViaController(descriptorFile.toString(), "alice@atlanta.com", "auto");

        try {
            Thread.sleep(3000);

            // Verify km-nostr-sa socket exists
            var socketResult = avatar.execInContainer("test", "-S",
                    "/tmp/keymaster-nostr-sa.sock");
            assertEquals(0, socketResult.getExitCode(),
                    "Nostr SA socket should exist. stderr: " + socketResult.getStderr());

            // Request public keys via km-nostr-sa
            String request = "{\"jsonrpc\":\"2.0\",\"method\":\"get_public_keys\",\"params\":{},\"id\":1}";
            String response = nostrSaRequest(avatar, request);
            log.info("get_public_keys response: {}", response);

            // Parse response — should contain at least one public key (64-char hex)
            var respObj = JsonParser.parseString(response).getAsJsonObject();
            assertNotNull(respObj.get("result"), "Response should have result. Full: " + response);
            var keys = respObj.getAsJsonArray("result");
            assertFalse(keys.isEmpty(), "Should have at least one public key");

            String pubkeyHex = keys.get(0).getAsJsonObject().get("public_key").getAsString();
            assertEquals(64, pubkeyHex.length(),
                    "Public key should be 64-char hex (32 bytes)");
            log.info("Nostr public key: {}", pubkeyHex);
        } finally {
            detachViaController();
            Thread.sleep(500);
        }
    }

    @Test
    @Order(34)
    void nostrSignEvent() throws Exception {
        Path descriptorFile = writeDescriptor("descriptor-nostr-sign.json", "nostr");

        attachViaController(descriptorFile.toString(), "alice@atlanta.com", "auto");

        try {
            Thread.sleep(3000);

            // First get the public key
            String keysRequest = "{\"jsonrpc\":\"2.0\",\"method\":\"get_public_keys\",\"params\":{},\"id\":1}";
            String keysResponse = nostrSaRequest(avatar, keysRequest);
            var keysObj = JsonParser.parseString(keysResponse).getAsJsonObject();
            String pubkeyHex = keysObj.getAsJsonArray("result")
                    .get(0).getAsJsonObject().get("public_key").getAsString();

            // Create a test event hash (32 bytes of 0xAB as hex)
            String eventHashHex = "ab".repeat(32);

            // Sign the event
            String signRequest = String.format(
                    "{\"jsonrpc\":\"2.0\",\"method\":\"sign_event\",\"params\":" +
                    "{\"public_key\":\"%s\",\"event_hash\":\"%s\"},\"id\":2}",
                    pubkeyHex, eventHashHex);
            String signResponse = nostrSaRequest(avatar, signRequest);
            log.info("sign_event response: {}", signResponse);

            var signObj = JsonParser.parseString(signResponse).getAsJsonObject();
            assertNotNull(signObj.get("result"),
                    "sign_event should have result. Full: " + signResponse);

            String sigHex = signObj.getAsJsonObject("result").get("signature").getAsString();
            assertEquals(128, sigHex.length(),
                    "Schnorr signature should be 128-char hex (64 bytes)");
            log.info("Schnorr signature: {}", sigHex);
        } finally {
            detachViaController();
            Thread.sleep(500);
        }
    }

    @Test
    @Order(35)
    void nostrNip04EncryptDecrypt() throws Exception {
        Path descriptorFile = writeDescriptor("descriptor-nostr-nip04.json", "nostr");

        attachViaController(descriptorFile.toString(), "alice@atlanta.com", "auto");

        try {
            Thread.sleep(3000);

            // Get Alice's public key
            String keysRequest = "{\"jsonrpc\":\"2.0\",\"method\":\"get_public_keys\",\"params\":{},\"id\":1}";
            String keysResponse = nostrSaRequest(avatar, keysRequest);
            var keysObj = JsonParser.parseString(keysResponse).getAsJsonObject();
            String alicePubkey = keysObj.getAsJsonArray("result")
                    .get(0).getAsJsonObject().get("public_key").getAsString();

            // NIP-04 encrypt (Alice encrypts to herself as peer for round-trip test)
            String plaintext = "hello-nip04-roundtrip";
            String encRequest = String.format(
                    "{\"jsonrpc\":\"2.0\",\"method\":\"nip04_encrypt\",\"params\":" +
                    "{\"public_key\":\"%s\",\"peer_public_key\":\"%s\",\"plaintext\":\"%s\"},\"id\":2}",
                    alicePubkey, alicePubkey, plaintext);
            String encResponse = nostrSaRequest(avatar, encRequest);
            log.info("nip04_encrypt response: {}", encResponse);

            var encObj = JsonParser.parseString(encResponse).getAsJsonObject();
            assertNotNull(encObj.get("result"),
                    "nip04_encrypt should have result. Full: " + encResponse);
            String ciphertext = encObj.getAsJsonObject("result").get("ciphertext").getAsString();
            assertFalse(ciphertext.isEmpty(), "Ciphertext should not be empty");
            assertTrue(ciphertext.contains("?iv="), "NIP-04 ciphertext should contain ?iv= separator");
            log.info("NIP-04 ciphertext: {}", ciphertext);

            // NIP-04 decrypt (same key pair — ECDH shared secret is identical)
            String decRequest = String.format(
                    "{\"jsonrpc\":\"2.0\",\"method\":\"nip04_decrypt\",\"params\":" +
                    "{\"public_key\":\"%s\",\"peer_public_key\":\"%s\",\"ciphertext\":\"%s\"},\"id\":3}",
                    alicePubkey, alicePubkey, ciphertext);
            String decResponse = nostrSaRequest(avatar, decRequest);
            log.info("nip04_decrypt response: {}", decResponse);

            var decObj = JsonParser.parseString(decResponse).getAsJsonObject();
            assertNotNull(decObj.get("result"),
                    "nip04_decrypt should have result. Full: " + decResponse);
            String decrypted = decObj.getAsJsonObject("result").get("plaintext").getAsString();
            assertEquals(plaintext, decrypted, "NIP-04 round-trip should recover original plaintext");
            log.info("NIP-04 round-trip OK: {}", decrypted);
        } finally {
            detachViaController();
            Thread.sleep(500);
        }
    }

    @Test
    @Order(36)
    void nostrNip44EncryptDecrypt() throws Exception {
        Path descriptorFile = writeDescriptor("descriptor-nostr-nip44.json", "nostr");

        attachViaController(descriptorFile.toString(), "alice@atlanta.com", "auto");

        try {
            Thread.sleep(3000);

            // Get Alice's public key
            String keysRequest = "{\"jsonrpc\":\"2.0\",\"method\":\"get_public_keys\",\"params\":{},\"id\":1}";
            String keysResponse = nostrSaRequest(avatar, keysRequest);
            var keysObj = JsonParser.parseString(keysResponse).getAsJsonObject();
            String alicePubkey = keysObj.getAsJsonArray("result")
                    .get(0).getAsJsonObject().get("public_key").getAsString();

            // NIP-44 encrypt (Alice encrypts to herself as peer for round-trip test)
            String plaintext = "hello-nip44-roundtrip";
            String encRequest = String.format(
                    "{\"jsonrpc\":\"2.0\",\"method\":\"nip44_encrypt\",\"params\":" +
                    "{\"public_key\":\"%s\",\"peer_public_key\":\"%s\",\"plaintext\":\"%s\"},\"id\":2}",
                    alicePubkey, alicePubkey, plaintext);
            String encResponse = nostrSaRequest(avatar, encRequest);
            log.info("nip44_encrypt response: {}", encResponse);

            var encObj = JsonParser.parseString(encResponse).getAsJsonObject();
            assertNotNull(encObj.get("result"),
                    "nip44_encrypt should have result. Full: " + encResponse);
            String ciphertext = encObj.getAsJsonObject("result").get("ciphertext").getAsString();
            assertFalse(ciphertext.isEmpty(), "Ciphertext should not be empty");
            log.info("NIP-44 ciphertext: {}", ciphertext);

            // NIP-44 decrypt (same key pair — ECDH shared secret is identical)
            String decRequest = String.format(
                    "{\"jsonrpc\":\"2.0\",\"method\":\"nip44_decrypt\",\"params\":" +
                    "{\"public_key\":\"%s\",\"peer_public_key\":\"%s\",\"ciphertext\":\"%s\"},\"id\":3}",
                    alicePubkey, alicePubkey, ciphertext);
            String decResponse = nostrSaRequest(avatar, decRequest);
            log.info("nip44_decrypt response: {}", decResponse);

            var decObj = JsonParser.parseString(decResponse).getAsJsonObject();
            assertNotNull(decObj.get("result"),
                    "nip44_decrypt should have result. Full: " + decResponse);
            String decrypted = decObj.getAsJsonObject("result").get("plaintext").getAsString();
            assertEquals(plaintext, decrypted, "NIP-44 round-trip should recover original plaintext");
            log.info("NIP-44 round-trip OK: {}", decrypted);
        } finally {
            detachViaController();
            Thread.sleep(500);
        }
    }

    @Test
    @Order(37)
    void nostrNip04EncryptDecryptWithNonKmPeer() throws Exception {
        Path descriptorFile = writeDescriptor("descriptor-nostr-nip04-xpeer.json", "nostr");

        attachViaController(descriptorFile.toString(), "alice@atlanta.com", "auto");

        try {
            Thread.sleep(3000);

            // Get Alice's (KM-managed) public key
            String keysRequest = "{\"jsonrpc\":\"2.0\",\"method\":\"get_public_keys\",\"params\":{},\"id\":1}";
            String keysResponse = nostrSaRequest(avatar, keysRequest);
            var keysObj = JsonParser.parseString(keysResponse).getAsJsonObject();
            String alicePubkeyHex = keysObj.getAsJsonArray("result")
                    .get(0).getAsJsonObject().get("public_key").getAsString();

            // Bob: generate ephemeral secp256k1 keypair (no KM)
            X9ECParameters secp = CustomNamedCurves.getByName("secp256k1");
            byte[] bobPrivKey = new byte[32];
            new SecureRandom().nextBytes(bobPrivKey);
            ECPoint bobPubPoint = secp.getG().multiply(new BigInteger(1, bobPrivKey)).normalize();
            byte[] bobPubKey = bobPubPoint.getAffineXCoord().getEncoded();
            String bobPubkeyHex = NostrUtil.bytesToHex(bobPubKey);

            // Bob computes ECDH shared secret with Alice
            byte[] alicePubBytes = NostrUtil.hexToBytes(alicePubkeyHex);
            ECPoint alicePoint = liftX(secp, alicePubBytes);
            byte[] sharedX = alicePoint.multiply(new BigInteger(1, bobPrivKey))
                    .normalize().getAffineXCoord().getEncoded();

            // --- Alice → Bob: KM encrypts, Bob decrypts ---
            String plaintext1 = "hello-nip04-alice-to-bob";
            String encRequest = String.format(
                    "{\"jsonrpc\":\"2.0\",\"method\":\"nip04_encrypt\",\"params\":" +
                    "{\"public_key\":\"%s\",\"peer_public_key\":\"%s\",\"plaintext\":\"%s\"},\"id\":2}",
                    alicePubkeyHex, bobPubkeyHex, plaintext1);
            String encResponse = nostrSaRequest(avatar, encRequest);
            var encObj = JsonParser.parseString(encResponse).getAsJsonObject();
            assertNotNull(encObj.get("result"),
                    "nip04_encrypt should have result. Full: " + encResponse);
            String ciphertext1 = encObj.getAsJsonObject("result").get("ciphertext").getAsString();

            // Bob decrypts locally using the shared secret
            String decrypted1 = nip04DecryptLocal(sharedX, ciphertext1);
            assertEquals(plaintext1, decrypted1,
                    "Bob (non-KM) should decrypt Alice's NIP-04 message");
            log.info("NIP-04 cross-peer Alice→Bob OK: {}", decrypted1);

            // --- Bob → Alice: Bob encrypts, KM decrypts ---
            String plaintext2 = "hello-nip04-bob-to-alice";
            String ciphertext2 = nip04EncryptLocal(sharedX, plaintext2);

            String decRequest = String.format(
                    "{\"jsonrpc\":\"2.0\",\"method\":\"nip04_decrypt\",\"params\":" +
                    "{\"public_key\":\"%s\",\"peer_public_key\":\"%s\",\"ciphertext\":\"%s\"},\"id\":3}",
                    alicePubkeyHex, bobPubkeyHex, ciphertext2);
            String decResponse = nostrSaRequest(avatar, decRequest);
            var decObj = JsonParser.parseString(decResponse).getAsJsonObject();
            assertNotNull(decObj.get("result"),
                    "nip04_decrypt should have result. Full: " + decResponse);
            String decrypted2 = decObj.getAsJsonObject("result").get("plaintext").getAsString();
            assertEquals(plaintext2, decrypted2,
                    "Alice (KM) should decrypt Bob's NIP-04 message");
            log.info("NIP-04 cross-peer Bob→Alice OK: {}", decrypted2);
        } finally {
            detachViaController();
            Thread.sleep(500);
        }
    }

    @Test
    @Order(38)
    void nostrNip44EncryptDecryptWithNonKmPeer() throws Exception {
        Path descriptorFile = writeDescriptor("descriptor-nostr-nip44-xpeer.json", "nostr");

        attachViaController(descriptorFile.toString(), "alice@atlanta.com", "auto");

        try {
            Thread.sleep(3000);

            // Get Alice's (KM-managed) public key
            String keysRequest = "{\"jsonrpc\":\"2.0\",\"method\":\"get_public_keys\",\"params\":{},\"id\":1}";
            String keysResponse = nostrSaRequest(avatar, keysRequest);
            var keysObj = JsonParser.parseString(keysResponse).getAsJsonObject();
            String alicePubkeyHex = keysObj.getAsJsonArray("result")
                    .get(0).getAsJsonObject().get("public_key").getAsString();

            // Bob: generate ephemeral secp256k1 keypair (no KM)
            X9ECParameters secp = CustomNamedCurves.getByName("secp256k1");
            byte[] bobPrivKey = new byte[32];
            new SecureRandom().nextBytes(bobPrivKey);
            ECPoint bobPubPoint = secp.getG().multiply(new BigInteger(1, bobPrivKey)).normalize();
            byte[] bobPubKey = bobPubPoint.getAffineXCoord().getEncoded();
            String bobPubkeyHex = NostrUtil.bytesToHex(bobPubKey);

            // Bob computes ECDH shared secret with Alice
            byte[] alicePubBytes = NostrUtil.hexToBytes(alicePubkeyHex);
            ECPoint alicePoint = liftX(secp, alicePubBytes);
            byte[] sharedX = alicePoint.multiply(new BigInteger(1, bobPrivKey))
                    .normalize().getAffineXCoord().getEncoded();

            // Derive NIP-44 conversation key from shared secret
            byte[] conversationKey = nip44ConversationKey(sharedX);

            // --- Alice → Bob: KM encrypts, Bob decrypts ---
            String plaintext1 = "hello-nip44-alice-to-bob";
            String encRequest = String.format(
                    "{\"jsonrpc\":\"2.0\",\"method\":\"nip44_encrypt\",\"params\":" +
                    "{\"public_key\":\"%s\",\"peer_public_key\":\"%s\",\"plaintext\":\"%s\"},\"id\":2}",
                    alicePubkeyHex, bobPubkeyHex, plaintext1);
            String encResponse = nostrSaRequest(avatar, encRequest);
            var encObj = JsonParser.parseString(encResponse).getAsJsonObject();
            assertNotNull(encObj.get("result"),
                    "nip44_encrypt should have result. Full: " + encResponse);
            String ciphertext1 = encObj.getAsJsonObject("result").get("ciphertext").getAsString();

            // Bob decrypts locally using conversation key
            String decrypted1 = EncryptedPayloads.decrypt(ciphertext1, conversationKey);
            assertEquals(plaintext1, decrypted1,
                    "Bob (non-KM) should decrypt Alice's NIP-44 message");
            log.info("NIP-44 cross-peer Alice→Bob OK: {}", decrypted1);

            // --- Bob → Alice: Bob encrypts, KM decrypts ---
            String plaintext2 = "hello-nip44-bob-to-alice";
            byte[] nonce = NostrUtil.createRandomByteArray(32);
            String ciphertext2 = EncryptedPayloads.encrypt(plaintext2, conversationKey, nonce);

            String decRequest = String.format(
                    "{\"jsonrpc\":\"2.0\",\"method\":\"nip44_decrypt\",\"params\":" +
                    "{\"public_key\":\"%s\",\"peer_public_key\":\"%s\",\"ciphertext\":\"%s\"},\"id\":3}",
                    alicePubkeyHex, bobPubkeyHex, ciphertext2);
            String decResponse = nostrSaRequest(avatar, decRequest);
            var decObj = JsonParser.parseString(decResponse).getAsJsonObject();
            assertNotNull(decObj.get("result"),
                    "nip44_decrypt should have result. Full: " + decResponse);
            String decrypted2 = decObj.getAsJsonObject("result").get("plaintext").getAsString();
            assertEquals(plaintext2, decrypted2,
                    "Alice (KM) should decrypt Bob's NIP-44 message");
            log.info("NIP-44 cross-peer Bob→Alice OK: {}", decrypted2);
        } finally {
            detachViaController();
            Thread.sleep(500);
        }
    }

    // ==================== MLS service avatar tests ====================

    @Test
    @Order(39)
    void mlsKeyDerivationSignAndHpke() throws Exception {
        Path descriptorFile = writeDescriptor("descriptor-nostr-mls.json", "nostr");

        attachViaController(descriptorFile.toString(), "alice@atlanta.com", "auto");

        try {
            Thread.sleep(3000);

            // 1. Get Nostr public key
            String keysRequest = "{\"jsonrpc\":\"2.0\",\"method\":\"get_public_keys\",\"params\":{},\"id\":1}";
            String keysResponse = nostrSaRequest(avatar, keysRequest);
            var keysObj = JsonParser.parseString(keysResponse).getAsJsonObject();
            String nostrPubkeyHex = keysObj.getAsJsonArray("result")
                    .get(0).getAsJsonObject().get("public_key").getAsString();
            log.info("Nostr pubkey: {}", nostrPubkeyHex);

            // 2. get_mls_pubkey — derive Ed25519 MLS signing key
            String mlsPubkeyReq = String.format(
                    "{\"jsonrpc\":\"2.0\",\"method\":\"get_mls_pubkey\",\"params\":" +
                    "{\"nostr_pubkey\":\"%s\",\"device_id\":null},\"id\":2}",
                    nostrPubkeyHex);
            String mlsPubkeyResp = nostrSaRequest(avatar, mlsPubkeyReq);
            log.info("get_mls_pubkey response: {}", mlsPubkeyResp);

            var mlsPubkeyObj = JsonParser.parseString(mlsPubkeyResp).getAsJsonObject();
            assertNotNull(mlsPubkeyObj.get("result"),
                    "get_mls_pubkey should have result. Full: " + mlsPubkeyResp);
            String mlsPubkeyHex = mlsPubkeyObj.getAsJsonObject("result")
                    .get("mls_pubkey").getAsString();
            assertEquals(64, mlsPubkeyHex.length(),
                    "MLS pubkey should be 64-char hex (32 bytes)");
            log.info("MLS pubkey: {}", mlsPubkeyHex);

            // 3. mls_sign — Ed25519 sign arbitrary data
            String dataHex = "ab".repeat(32);
            String mlsSignReq = String.format(
                    "{\"jsonrpc\":\"2.0\",\"method\":\"mls_sign\",\"params\":" +
                    "{\"mls_pubkey\":\"%s\",\"data\":\"%s\"},\"id\":3}",
                    mlsPubkeyHex, dataHex);
            String mlsSignResp = nostrSaRequest(avatar, mlsSignReq);
            log.info("mls_sign response: {}", mlsSignResp);

            var mlsSignObj = JsonParser.parseString(mlsSignResp).getAsJsonObject();
            assertNotNull(mlsSignObj.get("result"),
                    "mls_sign should have result. Full: " + mlsSignResp);
            String sigHex = mlsSignObj.getAsJsonObject("result")
                    .get("signature").getAsString();
            assertEquals(128, sigHex.length(),
                    "Ed25519 signature should be 128-char hex (64 bytes)");
            log.info("MLS signature: {}", sigHex);

            // 4. mls_hpke_pubkey_at — derive X25519 HPKE key at index 0
            String hpkePubkeyReq = String.format(
                    "{\"jsonrpc\":\"2.0\",\"method\":\"mls_hpke_pubkey_at\",\"params\":" +
                    "{\"mls_pubkey\":\"%s\",\"key_type\":0,\"index\":0},\"id\":4}",
                    mlsPubkeyHex);
            String hpkePubkeyResp = nostrSaRequest(avatar, hpkePubkeyReq);
            log.info("mls_hpke_pubkey_at response: {}", hpkePubkeyResp);

            var hpkePubkeyObj = JsonParser.parseString(hpkePubkeyResp).getAsJsonObject();
            assertNotNull(hpkePubkeyObj.get("result"),
                    "mls_hpke_pubkey_at should have result. Full: " + hpkePubkeyResp);
            String hpkePubkeyHex = hpkePubkeyObj.getAsJsonObject("result")
                    .get("hpke_pubkey").getAsString();
            assertEquals(64, hpkePubkeyHex.length(),
                    "HPKE X25519 pubkey should be 64-char hex (32 bytes)");
            log.info("HPKE pubkey: {}", hpkePubkeyHex);

            // 5. mls_hpke_dh — X25519 DH with a peer public key
            // Use a fixed 32-byte peer public key (X25519 basepoint = 9)
            String peerPublicHex = "09" + "00".repeat(31);
            String hpkeDhReq = String.format(
                    "{\"jsonrpc\":\"2.0\",\"method\":\"mls_hpke_dh\",\"params\":" +
                    "{\"hpke_pubkey\":\"%s\",\"peer_public\":\"%s\"},\"id\":5}",
                    hpkePubkeyHex, peerPublicHex);
            String hpkeDhResp = nostrSaRequest(avatar, hpkeDhReq);
            log.info("mls_hpke_dh response: {}", hpkeDhResp);

            var hpkeDhObj = JsonParser.parseString(hpkeDhResp).getAsJsonObject();
            assertNotNull(hpkeDhObj.get("result"),
                    "mls_hpke_dh should have result. Full: " + hpkeDhResp);
            String dhResultHex = hpkeDhObj.getAsJsonObject("result")
                    .get("dh_result").getAsString();
            assertEquals(64, dhResultHex.length(),
                    "DH result should be 64-char hex (32 bytes)");
            // DH with basepoint should equal the public key itself
            assertEquals(hpkePubkeyHex, dhResultHex,
                    "DH(basepoint) should equal the public key");
            log.info("HPKE DH result: {}", dhResultHex);

            // 6. sign_account_identity_proof — Schnorr sign Kind 450 event
            String proofReq = String.format(
                    "{\"jsonrpc\":\"2.0\",\"method\":\"sign_account_identity_proof\",\"params\":" +
                    "{\"account_identity\":\"%s\",\"mls_signature_public_key\":\"%s\"," +
                    "\"ciphersuite\":1,\"signature_scheme\":1},\"id\":6}",
                    nostrPubkeyHex, mlsPubkeyHex);
            String proofResp = nostrSaRequest(avatar, proofReq);
            log.info("sign_account_identity_proof response: {}", proofResp);

            var proofObj = JsonParser.parseString(proofResp).getAsJsonObject();
            assertNotNull(proofObj.get("result"),
                    "sign_account_identity_proof should have result. Full: " + proofResp);
            String proofSigHex = proofObj.getAsJsonObject("result")
                    .get("signature").getAsString();
            assertEquals(128, proofSigHex.length(),
                    "Schnorr signature should be 128-char hex (64 bytes)");
            log.info("Account identity proof signature: {}", proofSigHex);
        } finally {
            detachViaController();
            Thread.sleep(500);
        }
    }

    // ==================== Cross-peer crypto helpers ====================

    /**
     * Lift an x-only (32-byte) public key to a full EC point.
     * Picks the even-y coordinate per BIP-340.
     */
    private static ECPoint liftX(X9ECParameters curve, byte[] xBytes) {
        BigInteger x = new BigInteger(1, xBytes);
        BigInteger p = curve.getCurve().getField().getCharacteristic();
        BigInteger a = curve.getCurve().getA().toBigInteger();
        BigInteger b = curve.getCurve().getB().toBigInteger();

        // y^2 = x^3 + ax + b  (mod p)
        BigInteger rhs = x.modPow(BigInteger.valueOf(3), p)
                .add(a.multiply(x)).add(b).mod(p);
        BigInteger y = rhs.modPow(p.add(BigInteger.ONE).divide(BigInteger.valueOf(4)), p);
        // Pick even y
        if (y.testBit(0)) {
            y = p.subtract(y);
        }
        return curve.getCurve().createPoint(x, y);
    }

    /** NIP-04 encrypt locally using a pre-computed ECDH shared x-coordinate. */
    private static String nip04EncryptLocal(byte[] sharedX, String plaintext) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(sharedX, "AES");
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv));
        byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted)
                + "?iv=" + Base64.getEncoder().encodeToString(iv);
    }

    /** NIP-04 decrypt locally using a pre-computed ECDH shared x-coordinate. */
    private static String nip04DecryptLocal(byte[] sharedX, String ciphertext) throws Exception {
        String[] parts = ciphertext.split("\\?iv=");
        byte[] ct = Base64.getDecoder().decode(parts[0]);
        byte[] iv = Base64.getDecoder().decode(parts[1]);
        SecretKeySpec keySpec = new SecretKeySpec(sharedX, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));
        return new String(cipher.doFinal(ct), StandardCharsets.UTF_8);
    }

    /** Derive NIP-44 conversation key: HKDF-Extract(salt="nip44-v2", ikm=shared_x). */
    private static byte[] nip44ConversationKey(byte[] sharedX) throws Exception {
        byte[] salt = "nip44-v2".getBytes(StandardCharsets.UTF_8);
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(salt, "HmacSHA256"));
        return mac.doFinal(sharedX);
    }

    // ==================== Relay reconnect tests ====================
    // Test avatar recovery from relay disruptions (Mission 26.1.1.2).
    // Does not trigger D-Bus (no logind in containers) — validates
    // nostr-sdk auto-reconnect + re-subscribe.
    //
    // Note: a relay restart test (strfry container restart) is not
    // included because it also kills the daemon's relay connection,
    // and the Java core NostrTransport lacks auto-reconnect. The
    // Android client has reconnect (Mission 22.7) but it's not
    // available in the test harness. The network partition test
    // below is the correct E2E simulation: only the avatar loses
    // its connection while the daemon stays connected.

    @Test
    @Order(45)
    void relayNetworkPartitionRecovery() throws Exception {
        Path descriptorFile = writeDescriptor("descriptor-net-partition.json", "ssh");

        attachViaController(descriptorFile.toString(), "alice@atlanta.com", "auto");

        try {
            Thread.sleep(2000);

            // Verify SSH agent works before disruption
            var baseline = avatar.execInContainer("ssh-add", "-l");
            assertEquals(0, baseline.getExitCode(),
                    "ssh-add should work before network partition. stderr: " + baseline.getStderr());
            log.info("Baseline ssh-add OK before network partition");

            // Disconnect avatar from Docker network (simulates sleep/wake —
            // TCP connection dies but relay stays running)
            log.info("Disconnecting avatar from network...");
            var docker = DockerClientFactory.instance().client();
            docker.disconnectFromNetworkCmd()
                    .withContainerId(avatar.getContainerId())
                    .withNetworkId(network.getId())
                    .exec();

            Thread.sleep(5000);

            // Reconnect avatar to network (simulates wake)
            log.info("Reconnecting avatar to network...");
            docker.connectToNetworkCmd()
                    .withContainerId(avatar.getContainerId())
                    .withNetworkId(network.getId())
                    .withContainerNetwork(
                            new com.github.dockerjava.api.model.ContainerNetwork()
                                    .withAliases(java.util.List.of("avatar")))
                    .exec();

            log.info("Network reconnected, waiting for avatar to recover...");

            // Retry ssh-add — allow time for nostr-sdk auto-reconnect (~10s)
            var result = retrySshAdd(avatar, 8, 3000);
            assertEquals(0, result.getExitCode(),
                    "ssh-add should work after network partition (without re-attach). stderr: "
                            + result.getStderr());
            log.info("ssh-add OK after network partition: {}", result.getStdout().trim());
        } finally {
            // Ensure avatar is reconnected to the network for subsequent tests
            try {
                DockerClientFactory.instance().client()
                        .connectToNetworkCmd()
                        .withContainerId(avatar.getContainerId())
                        .withNetworkId(network.getId())
                        .withContainerNetwork(
                                new com.github.dockerjava.api.model.ContainerNetwork()
                                        .withAliases(java.util.List.of("avatar")))
                        .exec();
            } catch (Exception ignored) {
                // Already connected
            }
            detachViaController();
            Thread.sleep(500);
        }
    }

    /**
     * Retry ssh-add -l inside a container, returning the last result.
     * Gives nostr-sdk time to auto-reconnect after relay disruption.
     */
    private static org.testcontainers.containers.Container.ExecResult retrySshAdd(
            GenericContainer<?> container, int maxAttempts, long intervalMs) throws Exception {
        org.testcontainers.containers.Container.ExecResult result = null;
        for (int i = 1; i <= maxAttempts; i++) {
            result = container.execInContainer("ssh-add", "-l");
            log.info("ssh-add retry {}/{}: exit={}, stdout={}", i, maxAttempts,
                    result.getExitCode(), result.getStdout().trim());
            if (result.getExitCode() == 0) {
                return result;
            }
            if (i < maxAttempts) {
                Thread.sleep(intervalMs);
            }
        }
        return result;
    }

    // ==================== Packaged layout tests ====================
    // These test the "installed as a .deb" scenario: binaries in /usr/lib/keymaster-avatar/
    // (off PATH), avatar in /usr/bin/, config in /etc/keymaster-avatar/.
    // Avatar finds SAs via service_avatar_dir config; km-gpg-sa finds scd-shim via sibling lookup.

    @Test
    @Order(50)
    void packagedLayoutSshWorks() throws Exception {
        // Verify SAs are NOT on PATH — proves we're testing config-driven lookup
        var whichResult = avatarPackaged.execInContainer("which", "km-ssh-sa");
        assertNotEquals(0, whichResult.getExitCode(),
                "km-ssh-sa should NOT be on PATH in packaged layout");

        // Verify config was loaded
        String logs = avatarPackaged.getLogs();
        assertTrue(logs.contains("loaded config from /etc/keymaster-avatar/avatar.toml"),
                "Avatar should have loaded config from /etc/keymaster-avatar/avatar.toml");

        // Attach and test SSH agent
        Path descriptorFile = writeDescriptor("descriptor-pkg-ssh.json", "ssh",
                avatarPackagedLoginXpub);

        attachViaController(descriptorFile.toString(), "alice@atlanta.com", "auto");

        try {
            Thread.sleep(2000);

            // Verify SSH agent socket was created
            var socketResult = avatarPackaged.execInContainer("test", "-S",
                    "/tmp/keymaster-avatar-ssh-agent.sock");
            assertEquals(0, socketResult.getExitCode(),
                    "SSH agent socket should exist (packaged). stderr: " + socketResult.getStderr());

            // Run ssh-add -l
            var result = avatarPackaged.execInContainer("ssh-add", "-l");
            log.info("ssh-add (packaged) exit={}, stdout={}, stderr={}",
                    result.getExitCode(), result.getStdout(), result.getStderr());
            assertEquals(0, result.getExitCode(),
                    "ssh-add should list keys (packaged). stderr: " + result.getStderr());
        } finally {
            detachViaController();
            Thread.sleep(500);
        }
    }

    @Test
    @Order(60)
    void packagedLayoutGpgSignWorks() throws Exception {
        // Verify scd-shim is NOT on PATH — proves sibling lookup is needed
        var whichResult = avatarPackaged.execInContainer("which", "scd-shim");
        assertNotEquals(0, whichResult.getExitCode(),
                "scd-shim should NOT be on PATH in packaged layout");

        Path descriptorFile = writeDescriptor("descriptor-pkg-gpg.json", "gpg",
                avatarPackagedLoginXpub);

        attachViaController(descriptorFile.toString(), "alice@atlanta.com", "auto");

        try {
            // Wait for km-gpg-sa to complete GPG setup (LEARN, import, ownertrust, stubs).
            // Same timing as gpgSignAndVerify — direct attach is ~3s faster than subprocess.
            Thread.sleep(12000);

            // Sign a test message
            avatarPackaged.execInContainer("bash", "-c", "echo 'packaged test' > /tmp/test-pkg.txt");

            var signResult = avatarPackaged.execInContainer(
                    "gpg", "--homedir", "/tmp/gnupg-home",
                    "--batch", "--yes", "--clearsign",
                    "--pinentry-mode", "loopback", "--passphrase", "",
                    "/tmp/test-pkg.txt");
            log.info("GPG sign (packaged): exit={}, stdout={}, stderr={}",
                    signResult.getExitCode(), signResult.getStdout(), signResult.getStderr());
            assertEquals(0, signResult.getExitCode(),
                    "GPG clearsign should succeed (packaged). stderr: " + signResult.getStderr());

            // Verify the signature
            var verifyResult = avatarPackaged.execInContainer(
                    "gpg", "--homedir", "/tmp/gnupg-home",
                    "--batch", "--verify", "/tmp/test-pkg.txt.asc");
            log.info("GPG verify (packaged): exit={}, stdout={}, stderr={}",
                    verifyResult.getExitCode(), verifyResult.getStdout(), verifyResult.getStderr());
            assertEquals(0, verifyResult.getExitCode(),
                    "GPG verify should succeed (packaged). stderr: " + verifyResult.getStderr());
        } finally {
            detachViaController();
            Thread.sleep(500);
        }
    }

    // ==================== Helpers ====================

    /**
     * Write an avatar descriptor JSON file for the given service (uses default avatar).
     */
    private static Path writeDescriptor(String filename, String service) throws Exception {
        return writeDescriptor(filename, service, avatarLoginXpub);
    }

    /**
     * Write an avatar descriptor JSON file for the given service and login xpub.
     */
    private static Path writeDescriptor(String filename, String service, String loginXpub) throws Exception {
        String relayUrl = "ws://" + relay.getHost() + ":" + relay.getMappedPort(7777);
        String descriptorJson = String.format(
                "{\"relay\":\"%s\",\"login_xpub\":\"%s\",\"services\":[\"%s\"]}",
                relayUrl, loginXpub, service);
        Path file = kvHome.resolve(filename);
        Files.writeString(file, descriptorJson);
        return file;
    }

    /**
     * Attach to an avatar via direct controller call.
     */
    private static void attachViaController(String descriptorPath,
            String identity, String policy) {
        JsonObject params = new JsonObject();
        params.addProperty("descriptor", descriptorPath);
        params.addProperty("identity", identity);
        if (policy != null) params.addProperty("policy", policy);
        JsonObject result = daemonController.handle("session.attach", params);
        assertFalse(result.has("error"),
                "session.attach failed: " + result);
    }

    private static void detachViaController() {
        daemonController.handle("session.detach", new JsonObject());
    }

    /**
     * Send a JSON-RPC request to the km-nostr-sa socket inside a container
     * via a Python3 helper script. Returns the JSON-RPC response string.
     */
    private static String nostrSaRequest(GenericContainer<?> container, String requestJson) throws Exception {
        String script = String.join("\n",
                "import socket,struct,sys",
                "def recv_exact(s,n):",
                "  d=b''",
                "  while len(d)<n:",
                "    c=s.recv(n-len(d))",
                "    if not c: raise Exception('EOF')",
                "    d+=c",
                "  return d",
                "s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)",
                "s.connect('/tmp/keymaster-nostr-sa.sock')",
                "req=sys.argv[1].encode()",
                "s.sendall(struct.pack('>I',len(req))+req)",
                "n=struct.unpack('>I',recv_exact(s,4))[0]",
                "print(recv_exact(s,n).decode())",
                "s.close()");
        var result = container.execInContainer("python3", "-c", script, requestJson);
        if (result.getExitCode() != 0) {
            throw new RuntimeException("nostr-sa request failed (exit=" + result.getExitCode()
                    + "): " + result.getStderr());
        }
        return result.getStdout().trim();
    }

    /**
     * Create a KeyVault in-process (for SSH authorized_keys derivation only).
     */
    private static KeyVault createVaultInProcess() {
        return new Bip32KeyVault(TEST_MNEMONIC, "");
    }

    @AfterAll
    static void tearDown() {
        if (avatarPackaged != null) avatarPackaged.stop();
        if (avatar != null) avatar.stop();
        if (sshd != null) sshd.stop();
        if (relay != null) relay.stop();
        if (network != null) network.close();

        if (daemonController != null) daemonController.handle("session.detach", new JsonObject());
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
