import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
public class AESUtil {
    private static final String FIXED_BASE64_KEY = "bXlfc2VjcmV0X2tleTEyMw==";
    public static SecretKey secretKey = loadKey();
    private static SecretKey loadKey() {
         byte[] decodedKey = Base64.getDecoder().decode(FIXED_BASE64_KEY);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }
    public static String encrypt(String plain, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return Base64.getEncoder().encodeToString(cipher.doFinal(plain.getBytes()));
    }
    public static String decrypt(String cipherText, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return new String(cipher.doFinal(Base64.getDecoder().decode(cipherText)));
    }
}
