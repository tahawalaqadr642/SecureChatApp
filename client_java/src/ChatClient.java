import java.io.*;
import java.net.Socket;
import java.security.PublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;
public class ChatClient {
    private Socket socket;
    private DataOutputStream out;
    private DataInputStream in;
    private Consumer<String> onMessageReceived;
    private Consumer<FileReceiveRequest> onFileReceived;
    private String username;
    private final Map<String, FileReceiveRequest> pendingFileRequests = new HashMap<>();
    private int fileRequestCounter = 0;
    public static class FileReceiveRequest {
        private final String sender;
        private final String fileName;
        private final byte[] fileData;
        private final int requestId;
        public FileReceiveRequest(String sender, String fileName, byte[] fileData, int requestId) {
            this.sender = sender;
            this.fileName = fileName;
            this.fileData = fileData;
            this.requestId = requestId;
        }
        public String getSender() {
            return sender;
        }
        
        public String getFileName() {
            return fileName;
        }
        
        public byte[] getFileData() {
            return fileData;
        }
        
        public int getRequestId() {
            return requestId;
        }
        
        public long getFileSizeKB() {
            return fileData.length / 1024;
        }
    }
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
                            onMessageReceived.accept("🔐 AES key received and set from: " + targetUser);
                        }
                    } else {
                        try {
                            String decrypted = AESUtil.decrypt(msg, AESUtil.secretKey);

                            if (decrypted.startsWith("[FILE]||")) {
                                String[] hashParts = decrypted.split("::", 2);
                                if (hashParts.length == 2) {
                                    String fileContent = hashParts[0];
                                    String hash = hashParts[1];
                                    
                                    if (HashUtil.verifyHash(fileContent, hash)) {
                                        String[] parts = fileContent.split("\\|\\|", 4);
                                        if (parts.length == 4) {
                                            String sender = parts[1];
                                            String fileName = parts[2];
                                            try {
                                                byte[] fileData = Base64.getDecoder().decode(parts[3]);
                                                
                                                int requestId = ++fileRequestCounter;
                                                FileReceiveRequest request = new FileReceiveRequest(
                                                    sender, fileName, fileData, requestId);
                                                pendingFileRequests.put(String.valueOf(requestId), request);
                                                
                                                if (onFileReceived != null) {
                                                    onFileReceived.accept(request);
                                                }
                                            } catch (IllegalArgumentException e) {
                                                onMessageReceived.accept("⚠️ File decode error: " + e.getMessage());
                                                e.printStackTrace();
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
                                        String[] messageParts = plain.split(":", 2);
                                        if (messageParts.length == 2) {
                                            String sender = messageParts[0];
                                            String content = messageParts[1];
                                            onMessageReceived.accept(sender + ": " + content);
                                        } else {
                                            onMessageReceived.accept(plain);
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
                            e.printStackTrace();
                        }
                    }
                }
            } catch (Exception e) {
                onMessageReceived.accept("⚠️ Error: " + e.getMessage());
                e.printStackTrace();
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
            String fileMessage = "[FILE]||" + username + "||" + file.getName() + "||" + encoded;
            String hash = HashUtil.generateHash(fileMessage);
            String withHash = fileMessage + "::" + hash;
            String encrypted = AESUtil.encrypt(withHash, AESUtil.secretKey);
            out.writeUTF(encrypted);
        }
    }
    public void setOnMessageReceived(Consumer<String> callback) {
        this.onMessageReceived = callback;
    }
    public void setOnFileReceived(Consumer<FileReceiveRequest> callback) {
        this.onFileReceived = callback;
    }
    public FileReceiveRequest getFileRequest(String requestId) {
        return pendingFileRequests.get(requestId);
    }
    public void removeFileRequest(String requestId) {
        pendingFileRequests.remove(requestId);
    }
}