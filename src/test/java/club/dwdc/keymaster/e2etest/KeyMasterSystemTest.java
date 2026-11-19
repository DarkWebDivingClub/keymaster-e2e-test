package club.dwdc.keymaster.e2etest;

import club.dwdc.keyvault.core.Alg;
import club.dwdc.keyvault.core.UseField;
import club.dwdc.keyvault.core.Bip32KeyVault;
import club.dwdc.keyvault.core.ConfigField;
import club.dwdc.keyvault.core.KeyVault;
import club.dwdc.keyvault.core.Protocol;
import nostr.util.NostrUtil;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.Timeout;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * LXC-based system test for multi-identity KeyMaster deployment.
 *
 * <p>Provisions an unprivileged LXC container with the full KeyMaster stack
 * (strfry, km-avatar, km-daemon, km-ssh-sa, km-gpg-sa) and two users
 * (alice, bob). Tests multi-identity attach, identity CRUD, and user
 * isolation.
 *
 * <p>Run with: {@code mvn test -Psystem-test}
 *
 * <p>Requires LXC with unprivileged container support. Skipped on hosts
 * without LXC.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@Timeout(value = 5, unit = TimeUnit.MINUTES)
class KeyMasterSystemTest {

    private static final Logger log = LoggerFactory.getLogger(KeyMasterSystemTest.class);

    static final String CONTAINER = "km-systest";

    static final String ALICE_MNEMONIC =
            "abandon abandon abandon abandon abandon abandon " +
            "abandon abandon abandon abandon abandon about";

    static final String BOB_MNEMONIC =
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";

    static final int ALICE_UID = 1001;
    static final int BOB_UID = 1002;

    static final String DESCRIPTOR_PATH = "/run/keymaster-avatar/descriptor.json";

    /** Package paths — override with system properties. */
    private static final String STRFRY_DEB = System.getProperty("strfry.deb",
            "/home/rene/git/strfry_0.9.6-1_amd64.deb");
    private static final String AVATAR_DEB = System.getProperty("avatar.deb",
            "/home/rene/git/keymaster-avatar_0.2.0-3_amd64.deb");
    private static final String DESKTOP_DEB = System.getProperty("desktop.deb",
            "/home/rene/git/keymaster-desktop_0.2.0-1_all.deb");
    private static final String KEYVAULT_DEB = System.getProperty("keyvault.deb",
            "/home/rene/git/keyvault-cli_0.1.0_all.deb");

    private static Path rootfs;

    // ── Lifecycle ────────────────────────────────────────────────────────

    @BeforeAll
    static void provision() throws Exception {
        assumeTrue(lxcAvailable(), "LXC not available — skipping system test");

        // Destroy any leftover container
        exec("lxc-destroy", "-n", CONTAINER, "-f");

        log.info("Creating LXC container {}…", CONTAINER);
        execChecked("lxc-create", "-n", CONTAINER, "-t", "download",
                "--", "-d", "ubuntu", "-r", "resolute", "-a", "amd64");

        rootfs = Path.of(System.getProperty("user.home"),
                ".local/share/lxc/" + CONTAINER + "/rootfs");

        // Fix AppArmor for unprivileged containers
        Path config = Path.of(System.getProperty("user.home"),
                ".local/share/lxc/" + CONTAINER + "/config");
        Files.writeString(config,
                Files.readString(config) +
                "\nlxc.apparmor.profile = unconfined\n" +
                "lxc.apparmor.allow_incomplete = 1\n");

        execChecked("lxc-start", "-n", CONTAINER);
        waitForSystemd();

        installPackages();
        createUsers();
        writeSeeds();
        startDaemons();
        createIdentities();
        configureUserMapping();
        startAvatar();
        startServiceAvatars();
    }

    @AfterAll
    static void teardown() {
        try {
            // Dump logs for post-mortem
            log.info("=== km-avatar logs ===");
            lxcExecQuiet("journalctl", "-u", "km-avatar", "--no-pager", "-n", "50");
            log.info("=== strfry logs ===");
            lxcExecQuiet("journalctl", "-u", "strfry", "--no-pager", "-n", "10");
            log.info("=== alice km-daemon logs ===");
            lxcExecAsUserQuiet("alice", ALICE_UID,
                    "journalctl", "--user", "-u", "km-daemon", "--no-pager", "-n", "30");
            log.info("=== alice km-ssh-sa logs ===");
            lxcExecAsUserQuiet("alice", ALICE_UID,
                    "journalctl", "--user", "-u", "km-ssh-sa", "--no-pager", "-n", "20");
            log.info("=== alice km-gpg-sa logs ===");
            lxcExecAsUserQuiet("alice", ALICE_UID,
                    "journalctl", "--user", "-u", "km-gpg-sa", "--no-pager", "-n", "20");
            log.info("=== socket listing ===");
            lxcExecQuiet("ls", "-la", "/run/keymaster-avatar/");
            lxcExecQuiet("ls", "-la", "/run/user/" + ALICE_UID + "/");
        } catch (Exception e) {
            log.warn("Log dump failed", e);
        }

        try {
            exec("lxc-stop", "-n", CONTAINER);
        } catch (Exception e) {
            log.warn("Container stop failed", e);
        }
        try {
            exec("lxc-destroy", "-n", CONTAINER, "-f");
        } catch (Exception e) {
            log.warn("Container destroy failed", e);
        }
    }

    // ── Test cases ───────────────────────────────────────────────────────

    @Test
    @Order(1)
    void singleIdentityAttach() throws Exception {
        // Attach with primary identity only
        lxcExecAsUserChecked("alice", ALICE_UID,
                "km-cli", "attach", DESCRIPTOR_PATH,
                "--identity", "alice@atlanta.com", "--policy", "auto");

        try {
            // SSH agent should list one key
            String sshOut = lxcExecAsUserOutput("alice", ALICE_UID,
                    "ssh-add", "-l");
            log.info("ssh-add -l: {}", sshOut);
            // Count key lines (each line starts with key size)
            long sshKeyCount = sshOut.lines()
                    .filter(l -> l.matches("^\\d+\\s+.*"))
                    .count();
            assertEquals(1, sshKeyCount, "Should have 1 SSH key");

            // GPG should list keys — wait for km-gpg-sa to finish importing
            String gpgOut = waitForGpgKeys("alice", ALICE_UID, 15);
            log.info("gpg --list-keys: {}", gpgOut);
            assertTrue(gpgOut.contains("alice@atlanta.com"),
                    "GPG should list alice@atlanta.com");
        } finally {
            lxcExecAsUser("alice", ALICE_UID, "km-cli", "detach");
        }
    }

    @Test
    @Order(2)
    void multiIdentityAttach() throws Exception {
        // Attach with primary + secondary identity
        lxcExecAsUserChecked("alice", ALICE_UID,
                "km-cli", "attach", DESCRIPTOR_PATH,
                "--identity", "alice@atlanta.com",
                "--also", "alice@home.net",
                "--policy", "auto");

        try {
            // SSH agent should list 2 keys
            String sshOut = lxcExecAsUserOutput("alice", ALICE_UID,
                    "ssh-add", "-l");
            log.info("ssh-add -l (multi): {}", sshOut);
            long sshKeyCount = sshOut.lines()
                    .filter(l -> l.matches("^\\d+\\s+.*"))
                    .count();
            assertEquals(2, sshKeyCount, "Should have 2 SSH keys");
        } finally {
            lxcExecAsUser("alice", ALICE_UID, "km-cli", "detach");
        }
    }

    @Test
    @Order(3)
    void alsoKeyGpgOnly() throws Exception {
        // Attach with primary + GPG-only secondary
        lxcExecAsUserChecked("alice", ALICE_UID,
                "km-cli", "attach", DESCRIPTOR_PATH,
                "--identity", "alice@atlanta.com",
                "--also-key", "alice@wonder.land:gpg",
                "--policy", "auto");

        try {
            // SSH: should only have alice@atlanta.com (1 key)
            // This validates --also-key:gpg filtering (wonder.land excluded from SSH)
            String sshOut = lxcExecAsUserOutput("alice", ALICE_UID,
                    "ssh-add", "-l");
            log.info("ssh-add -l (gpg-only): {}", sshOut);
            long sshKeyCount = sshOut.lines()
                    .filter(l -> l.matches("^\\d+\\s+.*"))
                    .count();
            assertEquals(1, sshKeyCount,
                    "SSH should only have primary identity key");

            // GPG: primary identity should be present
            // Note: multi-identity GPG cert export (alice@wonder.land) is not yet
            // implemented in the avatar — only the primary identity cert is exported.
            String gpgOut = lxcExecAsUserOutput("alice", ALICE_UID,
                    "gpg", "--homedir",
                    "/run/user/" + ALICE_UID + "/gnupg-keymaster",
                    "--list-keys", "--with-colons");
            log.info("gpg --list-keys (gpg-only): {}", gpgOut);
            assertTrue(gpgOut.contains("alice@atlanta.com"),
                    "GPG should list alice@atlanta.com");
        } finally {
            lxcExecAsUser("alice", ALICE_UID, "km-cli", "detach");
        }
    }

    @Test
    @Order(4)
    void alsoKeySshOnly() throws Exception {
        // Attach with primary + SSH-only secondary
        lxcExecAsUserChecked("alice", ALICE_UID,
                "km-cli", "attach", DESCRIPTOR_PATH,
                "--identity", "alice@atlanta.com",
                "--also-key", "alice@home.net:ssh",
                "--policy", "auto");

        try {
            // SSH: should have 2 keys
            String sshOut = lxcExecAsUserOutput("alice", ALICE_UID,
                    "ssh-add", "-l");
            log.info("ssh-add -l (ssh-only): {}", sshOut);
            long sshKeyCount = sshOut.lines()
                    .filter(l -> l.matches("^\\d+\\s+.*"))
                    .count();
            assertEquals(2, sshKeyCount,
                    "SSH should have primary + ssh-only secondary");

            // GPG: should only have alice@atlanta.com (not alice@home.net)
            String gpgOut = lxcExecAsUserOutput("alice", ALICE_UID,
                    "gpg", "--homedir",
                    "/run/user/" + ALICE_UID + "/gnupg-keymaster",
                    "--list-keys", "--with-colons");
            log.info("gpg --list-keys (ssh-only): {}", gpgOut);
            assertTrue(gpgOut.contains("alice@atlanta.com"),
                    "GPG should list alice@atlanta.com");
            assertFalse(gpgOut.contains("alice@home.net"),
                    "GPG should NOT list alice@home.net");
        } finally {
            lxcExecAsUser("alice", ALICE_UID, "km-cli", "detach");
        }
    }

    @Test
    @Order(5)
    void gpgShowsCorrectName() throws Exception {
        // Attach with primary identity
        lxcExecAsUserChecked("alice", ALICE_UID,
                "km-cli", "attach", DESCRIPTOR_PATH,
                "--identity", "alice@atlanta.com", "--policy", "auto");

        try {
            // GPG uid should show "Alice", not email-as-name
            String gpgOut = lxcExecAsUserOutput("alice", ALICE_UID,
                    "gpg", "--homedir",
                    "/run/user/" + ALICE_UID + "/gnupg-keymaster",
                    "--list-keys", "--with-colons");
            log.info("gpg uid check: {}", gpgOut);
            // uid line format: uid:...:Alice <alice@atlanta.com>:...
            assertTrue(gpgOut.contains("Alice"),
                    "GPG uid should contain name 'Alice'");
        } finally {
            lxcExecAsUser("alice", ALICE_UID, "km-cli", "detach");
        }
    }

    @Test
    @Order(10)
    void identityDelete() throws Exception {
        // Verify alice@wonder.land exists
        String listBefore = lxcExecAsUserOutput("alice", ALICE_UID,
                "km-cli", "identity", "list");
        assertTrue(listBefore.contains("alice@wonder.land"),
                "alice@wonder.land should exist before delete");

        // Delete it
        lxcExecAsUserChecked("alice", ALICE_UID,
                "km-cli", "identity", "delete", "alice@wonder.land", "--force");

        // Verify it's gone
        String listAfter = lxcExecAsUserOutput("alice", ALICE_UID,
                "km-cli", "identity", "list");
        assertFalse(listAfter.contains("alice@wonder.land"),
                "alice@wonder.land should be gone after delete");
    }

    @Test
    @Order(11)
    void identityUpdate() throws Exception {
        // Update name on alice@atlanta.com
        lxcExecAsUserChecked("alice", ALICE_UID,
                "km-cli", "identity", "update", "alice@atlanta.com",
                "--name", "Alice Updated");

        // Verify the update via km-cli identity list
        String list = lxcExecAsUserOutput("alice", ALICE_UID,
                "km-cli", "identity", "list");
        log.info("identities after update: {}", list);
        assertTrue(list.contains("alice@atlanta.com"),
                "Updated identity should still exist");

        // Attach and verify SSH works with updated identity
        lxcExecAsUserChecked("alice", ALICE_UID,
                "km-cli", "attach", DESCRIPTOR_PATH,
                "--identity", "alice@atlanta.com", "--policy", "auto");

        try {
            String sshOut = lxcExecAsUserOutput("alice", ALICE_UID,
                    "ssh-add", "-l");
            log.info("ssh-add -l after update: {}", sshOut);
            assertTrue(sshOut.contains("alice@atlanta.com"),
                    "SSH should list updated identity");
        } finally {
            lxcExecAsUser("alice", ALICE_UID, "km-cli", "detach");
        }
    }

    @Test
    @Order(20)
    void userIsolation() throws Exception {
        // Alice's API socket should not be accessible by bob
        String aliceSocket = "/run/keymaster-avatar/api-" + ALICE_UID + ".sock";
        ExecResult result = lxcExecAsUserResult("bob", BOB_UID,
                "test", "-r", aliceSocket);
        assertNotEquals(0, result.exitCode(),
                "Bob should NOT be able to read alice's API socket");
    }

    // ── Provisioning helpers ─────────────────────────────────────────────

    private static void installPackages() throws Exception {
        log.info("Installing packages…");

        // Push .deb files into the container via lxc-attach stdin
        // (rootfs /tmp/ is tmpfs, rootfs /root/ is uid-mapped — neither works from host)
        lxcExecChecked("mkdir", "-p", "/root/debs");
        for (String deb : List.of(STRFRY_DEB, AVATAR_DEB, DESKTOP_DEB, KEYVAULT_DEB)) {
            Path src = Path.of(deb);
            assertTrue(Files.exists(src), "Package not found: " + deb);
            pushFileToContainer(src, "/root/debs/" + src.getFileName());
        }

        // Install Java runtime and base dependencies
        lxcExecChecked("apt-get", "update", "-qq");
        lxcExecChecked("apt-get", "install", "-y", "-qq",
                "openjdk-21-jre-headless", "gnupg", "openssh-client", "sudo");

        // Install .deb packages — dpkg may fail on unresolved deps
        ExecResult dpkgResult = lxcExec("dpkg", "-i",
                "/root/debs/" + Path.of(STRFRY_DEB).getFileName(),
                "/root/debs/" + Path.of(AVATAR_DEB).getFileName(),
                "/root/debs/" + Path.of(DESKTOP_DEB).getFileName(),
                "/root/debs/" + Path.of(KEYVAULT_DEB).getFileName());
        log.info("dpkg -i exit={}, output:\n{}", dpkgResult.exitCode(), dpkgResult.output());

        // Resolve any missing dependencies and configure
        lxcExecChecked("apt-get", "-f", "install", "-y", "-qq");
        // Reload systemd to pick up new unit files
        lxcExecChecked("systemctl", "daemon-reload");

        // Verify unit files are installed
        ExecResult unitCheck = lxcExec("ls", "-la",
                "/usr/lib/systemd/user/km-daemon.service",
                "/usr/lib/systemd/user/km-ssh-sa.service",
                "/usr/lib/systemd/user/km-gpg-sa.service",
                "/usr/lib/systemd/system/strfry.service",
                "/lib/systemd/system/km-avatar.service");
        log.info("Unit files:\n{}", unitCheck.output());

        // Stop services that auto-started — we'll configure first
        lxcExec("systemctl", "stop", "km-avatar");
    }

    private static void createUsers() throws Exception {
        log.info("Creating test users…");
        lxcExecChecked("useradd", "-m", "-s", "/bin/bash",
                "-u", String.valueOf(ALICE_UID), "alice");
        lxcExecChecked("useradd", "-m", "-s", "/bin/bash",
                "-u", String.valueOf(BOB_UID), "bob");

        // Enable linger so user services start at boot
        lxcExecChecked("loginctl", "enable-linger", "alice");
        lxcExecChecked("loginctl", "enable-linger", "bob");

        // Wait for user runtime dirs
        waitForPath("/run/user/" + ALICE_UID, 10);
        waitForPath("/run/user/" + BOB_UID, 10);
    }

    private static void writeSeeds() throws Exception {
        log.info("Writing seed files…");
        // Alice's seed — create config dirs with proper ownership
        lxcExecAsUserChecked("alice", ALICE_UID,
                "mkdir", "-p", "/home/alice/.config/keyvault");
        writeContainerFile("/home/alice/.config/keyvault/seed",
                ALICE_MNEMONIC + "\n\n", "alice", ALICE_UID);

        // Bob's seed
        lxcExecAsUserChecked("bob", BOB_UID,
                "mkdir", "-p", "/home/bob/.config/keyvault");
        writeContainerFile("/home/bob/.config/keyvault/seed",
                BOB_MNEMONIC + "\n\n", "bob", BOB_UID);

        // Avatar seed — raw 32-byte binary (avatar uses a different seed format)
        lxcExec("mkdir", "-p", "/var/lib/keymaster-avatar");
        byte[] avatarSeed = new byte[32];
        // Deterministic seed for test reproducibility: SHA-256("keymaster-test-avatar")
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            avatarSeed = md.digest("keymaster-test-avatar".getBytes(StandardCharsets.UTF_8));
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        pushBinaryToContainer(avatarSeed, "/var/lib/keymaster-avatar/seed");
        lxcExec("chown", "km-avatar:km-avatar", "/var/lib/keymaster-avatar/seed");
        lxcExec("chmod", "600", "/var/lib/keymaster-avatar/seed");
    }

    private static void startDaemons() throws Exception {
        log.info("Starting km-daemon for alice and bob…");
        // Reload user systemd to pick up new unit files
        lxcExecAsUserChecked("alice", ALICE_UID,
                "systemctl", "--user", "daemon-reload");
        lxcExecAsUserChecked("bob", BOB_UID,
                "systemctl", "--user", "daemon-reload");

        lxcExecAsUserChecked("alice", ALICE_UID,
                "systemctl", "--user", "start", "km-daemon");
        lxcExecAsUserChecked("bob", BOB_UID,
                "systemctl", "--user", "start", "km-daemon");

        // Wait for daemon sockets
        waitForPath("/run/user/" + ALICE_UID + "/keymaster.sock", 15);
        waitForPath("/run/user/" + BOB_UID + "/keymaster.sock", 15);
    }

    private static void createIdentities() throws Exception {
        log.info("Creating identities…");
        // Alice's identities
        lxcExecAsUserChecked("alice", ALICE_UID,
                "km-cli", "identity", "create", "alice@atlanta.com",
                "--name", "Alice");
        lxcExecAsUserChecked("alice", ALICE_UID,
                "km-cli", "identity", "create", "alice@home.net",
                "--name", "Alice Home");
        lxcExecAsUserChecked("alice", ALICE_UID,
                "km-cli", "identity", "create", "alice@wonder.land",
                "--name", "Alice Wonder");

        // Bob's identity
        lxcExecAsUserChecked("bob", BOB_UID,
                "km-cli", "identity", "create", "bob@biloxi.com",
                "--name", "Bob");

        // Verify identities
        String aliceList = lxcExecAsUserOutput("alice", ALICE_UID,
                "km-cli", "identity", "list");
        log.info("Alice identities: {}", aliceList);
        assertTrue(aliceList.contains("alice@atlanta.com"));
        assertTrue(aliceList.contains("alice@home.net"));
        assertTrue(aliceList.contains("alice@wonder.land"));
    }

    private static void configureUserMapping() throws Exception {
        log.info("Configuring user mapping…");
        // Derive Nostr pubkeys from mnemonics
        String alicePubkey = deriveNostrPubkey(ALICE_MNEMONIC, "alice@atlanta.com");
        String bobPubkey = deriveNostrPubkey(BOB_MNEMONIC, "bob@biloxi.com");
        log.info("Alice pubkey: {}", alicePubkey);
        log.info("Bob pubkey: {}", bobPubkey);

        String usersToml = """
                [[user]]
                npub = "%s"
                unix_user = "alice"

                [[user]]
                npub = "%s"
                unix_user = "bob"
                """.formatted(alicePubkey, bobPubkey);

        writeContainerFile("/etc/keymaster-avatar/users.toml",
                usersToml, "root", 0);
        // users.toml must be readable by km-avatar user (writeContainerFile uses 600)
        lxcExec("chmod", "644", "/etc/keymaster-avatar/users.toml");
    }

    private static void startAvatar() throws Exception {
        log.info("Starting strfry and km-avatar…");

        // Fix strfry nofiles limit for unprivileged container
        lxcExecChecked("sed", "-i", "s/nofiles = 1000000/nofiles = 0/",
                "/etc/strfry.conf");

        lxcExecChecked("systemctl", "start", "strfry");

        // Wait for strfry to be ready
        Thread.sleep(1000);

        // Start km-avatar
        lxcExecChecked("systemctl", "start", "km-avatar");

        // Wait for descriptor to appear
        waitForPath(DESCRIPTOR_PATH, 15);
        log.info("Avatar descriptor available at {}", DESCRIPTOR_PATH);
    }

    private static void startServiceAvatars() throws Exception {
        log.info("Starting service avatars…");
        // Start SSH and GPG service avatars for alice
        lxcExecAsUserChecked("alice", ALICE_UID,
                "systemctl", "--user", "start", "km-ssh-sa");
        lxcExecAsUserChecked("alice", ALICE_UID,
                "systemctl", "--user", "start", "km-gpg-sa");

        // Start SSH and GPG service avatars for bob
        lxcExecAsUserChecked("bob", BOB_UID,
                "systemctl", "--user", "start", "km-ssh-sa");
        lxcExecAsUserChecked("bob", BOB_UID,
                "systemctl", "--user", "start", "km-gpg-sa");

        // Give service avatars time to connect to the avatar API sockets
        Thread.sleep(3000);

        log.info("All services started.");
    }

    // ── Pubkey derivation ────────────────────────────────────────────────

    private static String deriveNostrPubkey(String mnemonic, String identity) {
        KeyVault vault = new Bip32KeyVault(mnemonic);
        int mangled = club.dwdc.keyvault.core.Bip32KeyDerivator.mangle(identity);
        int H = 0x80000000;
        int[] path = {
                44 | H,
                Protocol.NOSTR.coinType() | H,
                mangled | H,
                new UseField(0, 0).toIndex() | H,
                new ConfigField(ConfigField.CSPRNG_NONE, 0).toIndex() | H
        };
        return NostrUtil.bytesToHex(
                vault.execute(Alg.SECP256K1, KeyVault.FN_GET_PUBLIC_KEY, 0, null, path).data());
    }

    // ── Container file helpers ───────────────────────────────────────────

    /**
     * Push a binary file from the host into the container via lxc-attach stdin.
     */
    private static void pushFileToContainer(Path src, String destPath) throws Exception {
        log.debug("Pushing {} → {}", src, destPath);
        ProcessBuilder pb = new ProcessBuilder(
                "lxc-attach", "-n", CONTAINER, "--",
                "bash", "-c", "cat > " + destPath);
        pb.redirectErrorStream(true);
        Process p = pb.start();
        try (var out = p.getOutputStream();
             var in = Files.newInputStream(src)) {
            in.transferTo(out);
        }
        assertTrue(p.waitFor(120, TimeUnit.SECONDS), "File push timed out: " + destPath);
        assertEquals(0, p.exitValue(), "File push failed: " + destPath);
    }

    /**
     * Push raw bytes into a file in the container via lxc-attach stdin.
     */
    private static void pushBinaryToContainer(byte[] data, String destPath) throws Exception {
        log.debug("Pushing {} bytes → {}", data.length, destPath);
        ProcessBuilder pb = new ProcessBuilder(
                "lxc-attach", "-n", CONTAINER, "--",
                "bash", "-c", "cat > " + destPath);
        pb.redirectErrorStream(true);
        Process p = pb.start();
        p.getOutputStream().write(data);
        p.getOutputStream().close();
        assertTrue(p.waitFor(30, TimeUnit.SECONDS), "Binary push timed out: " + destPath);
        assertEquals(0, p.exitValue(), "Binary push failed: " + destPath);
    }

    private static void writeContainerFile(String path, String content,
                                           String owner, int uid) throws Exception {
        // Create parent directory
        String parentDir = path.substring(0, path.lastIndexOf('/'));
        lxcExec("mkdir", "-p", parentDir);

        // Write content via stdin pipe
        ProcessBuilder pb = new ProcessBuilder(
                "lxc-attach", "-n", CONTAINER, "--",
                "bash", "-c", "cat > " + path);
        pb.redirectErrorStream(true);
        Process p = pb.start();
        p.getOutputStream().write(content.getBytes(StandardCharsets.UTF_8));
        p.getOutputStream().close();
        assertTrue(p.waitFor(30, TimeUnit.SECONDS), "File write timed out");

        // Set ownership and permissions
        lxcExec("chmod", "600", path);
        if (uid >= 0) {
            lxcExec("chown", owner + ":" + owner, path);
        }
    }

    // ── Process execution helpers ────────────────────────────────────────

    record ExecResult(int exitCode, String output) {}

    private static boolean lxcAvailable() {
        try {
            Process p = new ProcessBuilder("lxc-create", "--version")
                    .redirectErrorStream(true).start();
            return p.waitFor(5, TimeUnit.SECONDS) && p.exitValue() == 0;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Run a command on the host. Ignores exit code.
     */
    private static ExecResult exec(String... cmd) throws Exception {
        log.debug("exec: {}", Arrays.asList(cmd));
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        Process p = pb.start();
        String output = readOutput(p);
        p.waitFor(60, TimeUnit.SECONDS);
        return new ExecResult(p.exitValue(), output);
    }

    /**
     * Run a command on the host. Fails test if exit code is non-zero.
     */
    private static ExecResult execChecked(String... cmd) throws Exception {
        ExecResult r = exec(cmd);
        assertEquals(0, r.exitCode(),
                "Command failed: " + Arrays.asList(cmd) + "\nOutput: " + r.output());
        return r;
    }

    /**
     * Run a command inside the container as root.
     */
    private static ExecResult lxcExec(String... cmd) throws Exception {
        List<String> full = new ArrayList<>();
        full.add("lxc-attach");
        full.add("-n");
        full.add(CONTAINER);
        full.add("--");
        full.addAll(Arrays.asList(cmd));
        return exec(full.toArray(new String[0]));
    }

    private static ExecResult lxcExecChecked(String... cmd) throws Exception {
        ExecResult r = lxcExec(cmd);
        assertEquals(0, r.exitCode(),
                "Container command failed: " + Arrays.asList(cmd) + "\nOutput: " + r.output());
        return r;
    }

    private static void lxcExecQuiet(String... cmd) {
        try {
            ExecResult r = lxcExec(cmd);
            if (!r.output().isBlank()) {
                log.info("{}", r.output());
            }
        } catch (Exception e) {
            log.warn("Quiet exec failed: {}", e.getMessage());
        }
    }

    /**
     * Run a command inside the container as a specific user.
     */
    private static ExecResult lxcExecAsUser(String user, int uid,
                                             String... cmd) throws Exception {
        // Build the command string for bash -c
        StringBuilder sb = new StringBuilder();
        sb.append("export XDG_RUNTIME_DIR=/run/user/").append(uid);
        sb.append(" DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/")
          .append(uid).append("/bus");
        sb.append(" SSH_AUTH_SOCK=/run/user/").append(uid)
          .append("/keymaster-ssh-agent.sock");
        sb.append(" && ");
        for (int i = 0; i < cmd.length; i++) {
            if (i > 0) sb.append(" ");
            // Quote arguments containing spaces
            if (cmd[i].contains(" ") || cmd[i].contains("'")) {
                sb.append("'").append(cmd[i].replace("'", "'\\''")).append("'");
            } else {
                sb.append(cmd[i]);
            }
        }

        return lxcExec("sudo", "-u", user, "bash", "-c", sb.toString());
    }

    private static ExecResult lxcExecAsUserChecked(String user, int uid,
                                                    String... cmd) throws Exception {
        ExecResult r = lxcExecAsUser(user, uid, cmd);
        assertEquals(0, r.exitCode(),
                "User command failed (" + user + "): " + Arrays.asList(cmd) +
                "\nOutput: " + r.output());
        return r;
    }

    private static String lxcExecAsUserOutput(String user, int uid,
                                               String... cmd) throws Exception {
        ExecResult r = lxcExecAsUser(user, uid, cmd);
        return r.output();
    }

    private static ExecResult lxcExecAsUserResult(String user, int uid,
                                                   String... cmd) throws Exception {
        return lxcExecAsUser(user, uid, cmd);
    }

    private static void lxcExecAsUserQuiet(String user, int uid, String... cmd) {
        try {
            ExecResult r = lxcExecAsUser(user, uid, cmd);
            if (!r.output().isBlank()) {
                log.info("{}", r.output());
            }
        } catch (Exception e) {
            log.warn("Quiet user exec failed: {}", e.getMessage());
        }
    }

    private static String readOutput(Process p) throws IOException {
        StringBuilder sb = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line).append("\n");
            }
        }
        return sb.toString().stripTrailing();
    }

    /**
     * Wait for systemd in the container to finish booting.
     */
    private static void waitForSystemd() throws Exception {
        log.info("Waiting for systemd…");
        for (int i = 0; i < 30; i++) {
            ExecResult r = lxcExec("systemctl", "is-system-running");
            String state = r.output().strip();
            if ("running".equals(state) || "degraded".equals(state)) {
                log.info("Systemd ready ({})", state);
                return;
            }
            Thread.sleep(1000);
        }
        fail("Systemd did not become ready within 30 seconds");
    }

    /**
     * Wait for GPG keys to be available (km-gpg-sa cert import may lag behind attach).
     */
    private static String waitForGpgKeys(String user, int uid,
                                          int timeoutSeconds) throws Exception {
        log.info("Waiting for GPG keys for {}…", user);
        for (int i = 0; i < timeoutSeconds; i++) {
            String gpgOut = lxcExecAsUserOutput(user, uid,
                    "gpg", "--homedir",
                    "/run/user/" + uid + "/gnupg-keymaster",
                    "--list-keys", "--with-colons");
            if (gpgOut.contains("pub:")) {
                return gpgOut;
            }
            Thread.sleep(1000);
        }
        fail("GPG keys not available within " + timeoutSeconds + "s for " + user);
        return null; // unreachable
    }

    /**
     * Wait for a path to appear inside the container.
     */
    private static void waitForPath(String path, int timeoutSeconds) throws Exception {
        log.info("Waiting for {}…", path);
        for (int i = 0; i < timeoutSeconds; i++) {
            ExecResult r = lxcExec("test", "-e", path);
            if (r.exitCode() == 0) {
                return;
            }
            Thread.sleep(1000);
        }
        fail("Path did not appear within " + timeoutSeconds + "s: " + path);
    }
}
