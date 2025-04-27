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
    private JFrame frame;
    private String username;
    public void create() {
        frame = new JFrame("Secure Chat");
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
                    showErrorDialog("Error sending message: " + ex.getMessage());
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
                    showErrorDialog("Error sending file: " + ex.getMessage());
                }
            }
        });
        client.setOnMessageReceived(msg -> {
            String timestamp = getTime();
            if (!msg.startsWith("📥") && !msg.startsWith("⚠️") && !msg.startsWith("🔐")){
                chatArea.append("[" + timestamp + "] " + replaceEmojis(msg) + "\n");
            } else {
                chatArea.append(msg + "\n");  
            }
        });
        client.setOnFileReceived(fileRequest -> {
            SwingUtilities.invokeLater(() -> {
                showFileDownloadPrompt(fileRequest);
            });
        });
        LoginDialog loginDialog = new LoginDialog(frame);
        loginDialog.setVisible(true);
        if (loginDialog.isSuccessful()) {
            username = loginDialog.getUsername();
            try {
                RSAUtil.initialize(username); 
                client.connect("localhost", 9999, username);
                chatArea.append("🔐 Connected as " + username + "\n");
                frame.setTitle("Secure Chat - " + username);
                frame.setVisible(true);
            } catch (Exception ex) {
                chatArea.append("❌ Connection failed: " + ex.getMessage() + "\n");
                showErrorDialog("Connection failed: " + ex.getMessage());
                System.exit(1);
            }
        } else {
            System.exit(0); 
        }
    }
    private void showFileDownloadPrompt(ChatClient.FileReceiveRequest fileRequest) {
        JDialog dialog = new JDialog(frame, "File Download Request", true);
        dialog.setSize(350, 200);
        dialog.setLocationRelativeTo(frame);
        dialog.setLayout(new BorderLayout());
        JPanel infoPanel = new JPanel(new GridLayout(3, 1, 5, 5));
        infoPanel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));
        infoPanel.add(new JLabel("<html><b>File download request from:</b> " + fileRequest.getSender() + "</html>"));
        infoPanel.add(new JLabel("<html><b>Filename:</b> " + fileRequest.getFileName() + "</html>"));
        infoPanel.add(new JLabel("<html><b>Size:</b> " + fileRequest.getFileSizeKB() + " KB</html>"));
        dialog.add(infoPanel, BorderLayout.CENTER);
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton acceptButton = new JButton("Accept & Download");
        JButton rejectButton = new JButton("Reject");
        buttonPanel.add(acceptButton);
        buttonPanel.add(rejectButton);
        dialog.add(buttonPanel, BorderLayout.SOUTH);
        acceptButton.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setSelectedFile(new File(fileRequest.getFileName()));
            int result = fileChooser.showSaveDialog(dialog);
            
            if (result == JFileChooser.APPROVE_OPTION) {
                File outputFile = fileChooser.getSelectedFile();
                try (FileOutputStream fos = new FileOutputStream(outputFile)) {
                    fos.write(fileRequest.getFileData());
                    chatArea.append("📥 Downloaded file from " + fileRequest.getSender() + 
                                   ": " + outputFile.getName() + "\n");
                } catch (Exception ex) {
                    chatArea.append("❌ Error saving file: " + ex.getMessage() + "\n");
                    showErrorDialog("Error saving file: " + ex.getMessage());
                }
            }
            
            client.removeFileRequest(String.valueOf(fileRequest.getRequestId()));
            dialog.dispose();
        });
        
        rejectButton.addActionListener(e -> {
            chatArea.append("🚫 Rejected file from " + fileRequest.getSender() + 
                           ": " + fileRequest.getFileName() + "\n");
            client.removeFileRequest(String.valueOf(fileRequest.getRequestId()));
            dialog.dispose();
        });
        
        dialog.setVisible(true);
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
    private void showErrorDialog(String message) {
        JOptionPane.showMessageDialog(frame, 
            message,
            "Error",
            JOptionPane.ERROR_MESSAGE);
    }
}