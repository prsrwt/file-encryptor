import javax.crypto.*;
        import javax.crypto.spec.*;
        import javax.swing.*;
        import java.awt.*;
import java.io.*;
        import java.nio.file.*;
        import java.security.*;

public class FileEncryptionApp extends JFrame {
    private JTextField fileField;
    private JPasswordField passwordField;
    private JTextArea logArea;

    public FileEncryptionApp() {
        setTitle("File Encryption App");
        setSize(500, 300);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setLayout(new BorderLayout());

        JPanel inputPanel = new JPanel(new GridLayout(3, 2, 5, 5));

        JLabel fileLabel = new JLabel("File:");
        inputPanel.add(fileLabel);

        fileField = new JTextField(20);
        inputPanel.add(fileField);

        JButton fileButton = new JButton("Browse");
        inputPanel.add(fileButton);

        JLabel passwordLabel = new JLabel("Password:");
        inputPanel.add(passwordLabel);

        passwordField = new JPasswordField(20);
        inputPanel.add(passwordField);

        JButton encryptButton = new JButton("Encrypt");
        inputPanel.add(encryptButton);

        JButton decryptButton = new JButton("Decrypt");
        inputPanel.add(decryptButton);

        add(inputPanel, BorderLayout.NORTH);

        logArea = new JTextArea(10, 40);
        logArea.setEditable(false);
        JScrollPane logScrollPane = new JScrollPane(logArea);
        add(logScrollPane, BorderLayout.CENTER);

        fileButton.addActionListener(e -> browseFile());
        encryptButton.addActionListener(e -> encryptFile());
        decryptButton.addActionListener(e -> decryptFile());
    }

    private void browseFile() {
        JFileChooser fileChooser = new JFileChooser();
        int returnValue = fileChooser.showOpenDialog(this);
        if (returnValue == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();
            fileField.setText(selectedFile.getAbsolutePath());
        }
    }

    private void encryptFile() {
        String filePath = fileField.getText();
        String password = new String(passwordField.getPassword());

        if (filePath.isEmpty() || password.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please select a file and enter a password.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        try {
            byte[] fileBytes = Files.readAllBytes(new File(filePath).toPath());

            // Generate a random IV
            SecureRandom random = new SecureRandom();
            byte[] ivBytes = new byte[16]; // IV length for AES is 16 bytes
            random.nextBytes(ivBytes);
            IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec secretKey = generateKey(password);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
            byte[] encryptedBytes = cipher.doFinal(fileBytes);

            String encryptedFilePath = filePath + ".encrypted";
            try (FileOutputStream outputStream = new FileOutputStream(encryptedFilePath)) {
                // Write IV followed by encrypted data
                outputStream.write(ivBytes);
                outputStream.write(encryptedBytes);
            }

            logArea.append("File encrypted successfully. Encrypted file saved as: " + encryptedFilePath + "\n");
        } catch (Exception e) {
            logArea.append("Error: " + e.getMessage() + "\n");
        }
    }

    private void decryptFile() {
        String filePath = fileField.getText();
        String password = new String(passwordField.getPassword());

        if (filePath.isEmpty() || password.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please select a file and enter a password.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        try (FileInputStream inputStream = new FileInputStream(filePath)) {
            // Read IV
            byte[] ivBytes = new byte[16]; // IV length for AES is 16 bytes
            inputStream.read(ivBytes);
            IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

            byte[] encryptedBytes = inputStream.readAllBytes();

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec secretKey = generateKey(password);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

            String decryptedFilePath = filePath.replace(".encrypted", ".decrypted");
            try (FileOutputStream outputStream = new FileOutputStream(decryptedFilePath)) {
                outputStream.write(decryptedBytes);
            }

            logArea.append("File decrypted successfully. Decrypted file saved as: " + decryptedFilePath + "\n");
        } catch (Exception e) {
            logArea.append("Error: " + e.getMessage() + "\n");
        }
    }

    private SecretKeySpec generateKey(String password) throws NoSuchAlgorithmException {
        final MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] bytes = password.getBytes();
        digest.update(bytes, 0, bytes.length);
        byte[] key = digest.digest();
        return new SecretKeySpec(key, "AES");
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            FileEncryptionApp app = new FileEncryptionApp();
            app.setVisible(true);
        });
    }
}