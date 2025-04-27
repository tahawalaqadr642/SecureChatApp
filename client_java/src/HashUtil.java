import java.security.MessageDigest;
public class HashUtil {
    public static String generateHash(String msg) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(msg.getBytes("UTF-8"));
        StringBuilder hex = new StringBuilder();
        for (byte b : hash) {
            hex.append(String.format("%02x", b));
        }
        return hex.toString();
    }
    public static boolean verifyHash(String msg, String hash) throws Exception {
        return generateHash(msg).equals(hash);
    }
}
