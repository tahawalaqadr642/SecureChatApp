import java.util.HashMap;
public class PublicKeyExchange {
    public static HashMap<String, String> publicKeys = new HashMap<>();

    public static void add(String username, String pubKey) {
        publicKeys.put(username, pubKey);
    }
    public static String get(String username) {
        return publicKeys.get(username);
    }
}
