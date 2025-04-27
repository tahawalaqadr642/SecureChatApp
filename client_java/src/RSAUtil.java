import java.io.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import javax.crypto.Cipher;

public class RSAUtil {
    public static KeyPair keyPair;

    public static void initialize(String username) {
        try {
            File privateKeyFile = new File(username + "_private.key");
            File publicKeyFile = new File(username + "_public.key");

            if (privateKeyFile.exists() && publicKeyFile.exists()) {
                keyPair = loadKeyPair(username);
                System.out.println("🔐 Loaded existing RSA key pair for " + username);
            } else {
                keyPair = generateKeyPair();
                saveKeyPair(username, keyPair);
                System.out.println("🔐 Generated and saved new RSA key pair for " + username);
            }
        } catch (Exception e) {
            throw new RuntimeException("RSA initialization failed: " + e.getMessage());
        }
    }

    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return gen.generateKeyPair();
    }

    private static void saveKeyPair(String username, KeyPair pair) throws IOException {
        try (FileOutputStream out = new FileOutputStream(username + "_private.key")) {
            out.write(pair.getPrivate().getEncoded());
        }
        try (FileOutputStream out = new FileOutputStream(username + "_public.key")) {
            out.write(pair.getPublic().getEncoded());
        }
    }

    private static KeyPair loadKeyPair(String username) throws Exception {
        byte[] privBytes;
        byte[] pubBytes;
        try (FileInputStream privIn = new FileInputStream(username + "_private.key");
             FileInputStream pubIn = new FileInputStream(username + "_public.key")) {
            privBytes = privIn.readAllBytes();
            pubBytes = pubIn.readAllBytes();
        }
        PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privBytes);
        X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubBytes);
    
        KeyFactory factory = KeyFactory.getInstance("RSA");
        PrivateKey priv = factory.generatePrivate(privSpec);
        PublicKey pub = factory.generatePublic(pubSpec);
    
        return new KeyPair(pub, priv);
    }
    public static String encrypt(String plain, PublicKey pubKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        return Base64.getEncoder().encodeToString(cipher.doFinal(plain.getBytes()));
    }

    public static String decrypt(String cipherText, PrivateKey privKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privKey);
        return new String(cipher.doFinal(Base64.getDecoder().decode(cipherText)));
    }

    public static String getPublicKeyString() {
        return Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
    }

    public static PublicKey loadPublicKey(String base64) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(base64);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(new X509EncodedKeySpec(keyBytes));
    }
}
