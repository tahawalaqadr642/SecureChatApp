import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.text.SimpleDateFormat;
import java.util.Date;
import javax.swing.*;

public class GUI {
    private final ChatClient client = new ChatClient();
    private final JTextArea chatArea = new JTextArea();
    private final JTextField inputField = new JTextField();
    private final JButton sendButton = new JButton("Send");
    private final JButton fileButton = new JButton("📎");

    public void create() {
        JFrame frame = new JFrame("Secure Chat");
        frame.setSize(500, 550);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setLayout(new BorderLayout());

        chatArea.setEditable(false);
        chatArea.setLineWrap(true);
        chatArea.setWrapStyleWord(true);
        JScrollPane scrollPane = new JScrollPane(chatArea);
        frame.add(scrollPane, BorderLayout.CENTER);

        JPanel inputPanel = new JPanel(new BorderLayout(5, 5));
        inputPanel.add(fileButton, BorderLayout.WEST);
        inputPanel.add(inputField, BorderLayout.CENTER);
        inputPanel.add(sendButton, BorderLayout.EAST);
        frame.add(inputPanel, BorderLayout.SOUTH);

        ActionListener sendAction = e -> {
            String msg = inputField.getText().trim();
            if (!msg.isEmpty()) {
                inputField.setText("");
                try {
                    String timestamp = getTime();
                    client.sendMessage(msg); 
                    chatArea.append("Me [" + timestamp + "]: " + replaceEmojis(msg) + "\n");  
                } catch (Exception ex) {
                    chatArea.append("❌ Error sending message\n");
                    ex.printStackTrace(); // For debugging
                }
            }
        };

        inputField.addActionListener(sendAction);
        sendButton.addActionListener(sendAction);

        fileButton.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            int result = fileChooser.showOpenDialog(frame);
            if (result == JFileChooser.APPROVE_OPTION) {
                File file = fileChooser.getSelectedFile();
                try {
                    client.sendFile(file);
                    chatArea.append("📤 Sent file: " + file.getName() + "\n");
                } catch (Exception ex) {
                    chatArea.append("❌ Error sending file: " + ex.getMessage() + "\n");
                    ex.printStackTrace(); // For debugging
                }
            }
        });

        client.setOnMessageReceived(msg -> {
            String timestamp = getTime();
            if (!msg.startsWith("📥") && !msg.startsWith("⚠️")) {
                chatArea.append("[" + timestamp + "] " + replaceEmojis(msg) + "\n");
            } else {
                chatArea.append(replaceEmojis(msg) + "\n");  // System messages
            }
        });

        try {
            String username = JOptionPane.showInputDialog("Enter your username:");
            if (username == null || username.trim().isEmpty()) {
                username = "User" + System.currentTimeMillis() % 1000;  // Fallback username
            }
            
            RSAUtil.initialize(username); 
            client.connect("localhost", 9999, username);
            chatArea.append("🔐 Connected as " + username + "\n");
        } catch (Exception e) {
            chatArea.append("❌ Connection failed: " + e.getMessage() + "\n");
            System.err.println("An unexpected error occurred: " + e.getMessage()); // For debugging
        }

        frame.setVisible(true);
    }

    private String getTime() {
        return new SimpleDateFormat("HH:mm:ss").format(new Date());
    }

    private String replaceEmojis(String msg) {
        return msg.replace(":)", "😊")
                  .replace(":(", "😢")
                  .replace(":D", "😄")
                  .replace("<3", "❤️");
    }
}