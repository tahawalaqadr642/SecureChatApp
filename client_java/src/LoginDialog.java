import java.awt.*;
import java.awt.event.*;
import javax.swing.*;

public class LoginDialog extends JDialog {
    private JTextField usernameField;
    private JPasswordField passwordField;
    private JButton loginButton;
    private JButton registerButton;
    private boolean isSuccess = false;
    private String username;

    public LoginDialog(Frame parent) {
        super(parent, "Login", true);
        setSize(320, 200);
        setLocationRelativeTo(parent);
        setResizable(false);
        setLayout(new BorderLayout());

        JPanel panel = new JPanel(new GridLayout(3, 2, 10, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));

        panel.add(new JLabel("Username:"));
        usernameField = new JTextField();
        panel.add(usernameField);

        panel.add(new JLabel("Password:"));
        passwordField = new JPasswordField();
        panel.add(passwordField);

        registerButton = new JButton("Register");
        loginButton = new JButton("Login");
        panel.add(registerButton);
        panel.add(loginButton);

        add(panel, BorderLayout.CENTER);

        registerButton.addActionListener(e -> {
            username = usernameField.getText().trim();
            String password = new String(passwordField.getPassword());

            if (username.isEmpty() || password.isEmpty()) {
                JOptionPane.showMessageDialog(this,
                        "Username and password cannot be empty",
                        "Registration Error",
                        JOptionPane.ERROR_MESSAGE);
                return;
            }

            if (User.register(username, password)) {
                JOptionPane.showMessageDialog(this,
                        "Registration successful. You can now login.",
                        "Registration",
                        JOptionPane.INFORMATION_MESSAGE);
            } else {
                JOptionPane.showMessageDialog(this,
                        "Username already exists",
                        "Registration Error",
                        JOptionPane.ERROR_MESSAGE);
            }
        });

        loginButton.addActionListener(e -> {
            username = usernameField.getText().trim();
            String password = new String(passwordField.getPassword());

            if (username.isEmpty() || password.isEmpty()) {
                JOptionPane.showMessageDialog(this,
                        "Username and password cannot be empty",
                        "Login Error",
                        JOptionPane.ERROR_MESSAGE);
                return;
            }

            if (User.authenticate(username, password)) {
                isSuccess = true;
                dispose();
            } else {
                JOptionPane.showMessageDialog(this,
                        "Invalid username or password",
                        "Login Error",
                        JOptionPane.ERROR_MESSAGE);
            }
        });

        Action enterAction = new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                loginButton.doClick();
            }
        };
        passwordField.getInputMap().put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0), "enter");
        passwordField.getActionMap().put("enter", enterAction);
    }
    public boolean isSuccessful() {
        return isSuccess;
    }
    public String getUsername() {
        return username;
    }
}
