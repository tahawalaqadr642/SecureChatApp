import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
public class User implements Serializable {
    private static final long serialVersionUID = 1L;
    private static final String USERS_FILE = "users.dat";
    private static final String SALT_FILE = "salt.dat";
    private static final int ITERATIONS = 65536;
    private static final int KEY_LENGTH = 256;
    private final String username;
    private final byte[] passwordHash;
    private final byte[] salt;
    private static Map<String, User> users = new HashMap<>();
    private static byte[] masterSalt;
    static {
        loadUsers();
        initializeSalt();
    }
    private User(String username, String password) {
        this.username = username;
        this.salt = generateSalt();
        this.passwordHash = hashPassword(password, salt);
    }
    private static void initializeSalt() {
        try {
            File saltFile = new File(SALT_FILE);
            if (saltFile.exists()) {
                masterSalt = Files.readAllBytes(Paths.get(SALT_FILE));
            } else {
                SecureRandom random = new SecureRandom();
                masterSalt = new byte[16];
                random.nextBytes(masterSalt);
                Files.write(Paths.get(SALT_FILE), masterSalt);
            }
        } catch (IOException e) {
            System.err.println("Error initializing salt: " + e.getMessage());
        }
    }

    private byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] newSalt = new byte[16];
        random.nextBytes(newSalt);
        return newSalt;
    }

    private byte[] hashPassword(String password, byte[] salt) {
        try {
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return factory.generateSecret(spec).getEncoded();
        } catch (Exception e) {
            throw new RuntimeException("Error hashing password", e);
        }
    }
    public static boolean register(String username, String password) {
        if (users.containsKey(username)) {
            return false; 
        }
        User newUser = new User(username, password);
        users.put(username, newUser);
        saveUsers();
        return true;
    }
    public static boolean authenticate(String username, String password) {
        User user = users.get(username);
        if (user == null) {
            return false;
        }

        byte[] hash = user.hashPassword(password, user.salt);
        return Arrays.equals(hash, user.passwordHash);
    }
    private static void saveUsers() {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            SecretKey key = new SecretKeySpec(deriveKeyFromMasterSalt(), "AES");
            cipher.init(Cipher.ENCRYPT_MODE, key);

            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            try (ObjectOutputStream oos = new ObjectOutputStream(bos)) {
                oos.writeObject(users);
            }

            byte[] encrypted = cipher.doFinal(bos.toByteArray());

            try (FileOutputStream fos = new FileOutputStream(USERS_FILE)) {
                fos.write(encrypted);
            }
        } catch (Exception e) {
            System.err.println("Error saving users: " + e.getMessage());
        }
    }
    @SuppressWarnings("unchecked")
    private static void loadUsers() {
        File file = new File(USERS_FILE);
        if (!file.exists()) {
            users = new HashMap<>();
            return;
        }
        try {
            byte[] fileData = Files.readAllBytes(Paths.get(USERS_FILE));
            if (new File(SALT_FILE).exists()) {
                masterSalt = Files.readAllBytes(Paths.get(SALT_FILE));
                Cipher cipher = Cipher.getInstance("AES");
                SecretKey key = new SecretKeySpec(deriveKeyFromMasterSalt(), "AES");
                cipher.init(Cipher.DECRYPT_MODE, key);
                byte[] decrypted = cipher.doFinal(fileData);

                try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(decrypted))) {
                    users = (Map<String, User>) ois.readObject();
                }
            } else {
                users = new HashMap<>();
            }
        } catch (Exception e) {
            System.err.println("Error loading users: " + e.getMessage());
            users = new HashMap<>();
        }
    }
    private static byte[] deriveKeyFromMasterSalt() {
        try {
            KeySpec spec = new PBEKeySpec("MasterPassword".toCharArray(), masterSalt, ITERATIONS, KEY_LENGTH);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return factory.generateSecret(spec).getEncoded();
        } catch (Exception e) {
            throw new RuntimeException("Error deriving key from master salt", e);
        }
    }
    public String getUsername() {
        return username;
    }
}
