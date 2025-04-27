import java.io.*;
import java.net.Socket;
import java.security.PublicKey;
import java.util.Base64;
import java.util.function.Consumer;

public class ChatClient {
    private Socket socket;
    private DataOutputStream out;
    private DataInputStream in;
    private Consumer<String> onMessageReceived;
    private String username;

    public void connect(String host, int port, String username) throws Exception {
        this.username = username;
        socket = new Socket(host, port);
        out = new DataOutputStream(socket.getOutputStream());
        in = new DataInputStream(socket.getInputStream());

        out.writeUTF("PUBKEY::" + username + "::" + RSAUtil.getPublicKeyString());

        new Thread(() -> {
            try {
                while (true) {
                    String msg = in.readUTF();

                    if (msg.startsWith("PUBKEY::")) {
                        String[] parts = msg.split("::");
                        String user = parts[1];
                        String pubKeyStr = parts[2];
                        if (!user.equals(this.username)) {
                            PublicKeyExchange.add(user, pubKeyStr);
                            PublicKey otherPubKey = RSAUtil.loadPublicKey(pubKeyStr);
                            String aesKeyEncoded = Base64.getEncoder().encodeToString(AESUtil.secretKey.getEncoded());
                            String aesKeyEncrypted = RSAUtil.encrypt(aesKeyEncoded, otherPubKey);
                            out.writeUTF("AESKEY::" + user + "::" + aesKeyEncrypted);
                        }
                    } else if (msg.startsWith("AESKEY::")) {
                        String[] parts = msg.split("::");
                        String targetUser = parts[1];
                        String encryptedAesKey = parts[2];
                        if (targetUser.equals(this.username)) {
                            String aesKeyDecoded = RSAUtil.decrypt(encryptedAesKey, RSAUtil.keyPair.getPrivate());
                            AESUtil.secretKey = new javax.crypto.spec.SecretKeySpec(Base64.getDecoder().decode(aesKeyDecoded), "AES");
                            System.out.println("🔐 AES key received and set from: " + targetUser);
                        }
                    } else {
                        try {
                            String decrypted = AESUtil.decrypt(msg, AESUtil.secretKey);

                            if (decrypted.startsWith("[FILE]||")) {
                                // Extract the content part (without the hash)
                                String[] hashParts = decrypted.split("::", 2);
                                if (hashParts.length == 2) {
                                    String fileContent = hashParts[0];
                                    String hash = hashParts[1];
                                    
                                    // Verify hash
                                    if (HashUtil.verifyHash(fileContent, hash)) {
                                        // Now process the file content
                                        String[] parts = fileContent.split("\\|\\|", 3);
                                        if (parts.length == 3) {
                                            String fileName = parts[1];
                                            try {
                                                byte[] fileData = Base64.getDecoder().decode(parts[2]);
                                                File outputFile = new File("received_" + fileName);
                                                try (FileOutputStream fos = new FileOutputStream(outputFile)) {
                                                    fos.write(fileData);
                                                }
                                                onMessageReceived.accept("📥 Received file: " + outputFile.getName());
                                            } catch (IllegalArgumentException e) {
                                                // Base64 decoding failed
                                                onMessageReceived.accept("⚠️ File decode error: " + e.getMessage());
                                            }
                                        } else {
                                            onMessageReceived.accept("⚠️ Malformed file message structure.");
                                        }
                                    } else {
                                        onMessageReceived.accept("⚠️ File integrity check failed.");
                                    }
                                } else {
                                    onMessageReceived.accept("⚠️ Malformed file message (missing hash).");
                                }
                            } else {
                                String[] parts = decrypted.split("::", 2);
                                if (parts.length == 2) {
                                    String hash = parts[1];
                                    String plain = parts[0];
                                    if (HashUtil.verifyHash(plain, hash)) {
                                        // Split to get username and message
                                        String[] messageParts = plain.split(":", 2);
                                        if (messageParts.length == 2) {
                                            String sender = messageParts[0];
                                            String content = messageParts[1];
                                            onMessageReceived.accept(sender + ": " + content);
                                        } else {
                                            onMessageReceived.accept(plain); // Fallback for old format
                                        }
                                    } else {
                                        onMessageReceived.accept("⚠️ Message integrity check failed.");
                                    }
                                } else {
                                    onMessageReceived.accept("⚠️ Malformed message received.");
                                }
                            }
                        } catch (Exception e) {
                            onMessageReceived.accept("⚠️ Decryption error: " + e.getMessage());
                            e.printStackTrace(); // For debugging
                        }
                    }
                }
            } catch (Exception e) {
                onMessageReceived.accept("⚠️ Error: " + e.getMessage());
                e.printStackTrace(); // For debugging
            }
        }).start();
    }

    public void sendMessage(String msg) throws Exception {
        String messageWithUser = username + ":" + msg;
        String hash = HashUtil.generateHash(messageWithUser);
        String withHash = messageWithUser + "::" + hash;
        String encrypted = AESUtil.encrypt(withHash, AESUtil.secretKey);
        out.writeUTF(encrypted);
    }

    public void sendFile(File file) throws Exception {
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] fileBytes = fis.readAllBytes();
            String encoded = Base64.getEncoder().encodeToString(fileBytes);
            String fileMessage = "[FILE]||" + file.getName() + "||" + encoded;
            String hash = HashUtil.generateHash(fileMessage);
            String withHash = fileMessage + "::" + hash;
            String encrypted = AESUtil.encrypt(withHash, AESUtil.secretKey);
            out.writeUTF(encrypted);
        }
    }
    public void setOnMessageReceived(Consumer<String> callback) {
        this.onMessageReceived = callback;
    }
}