package com.simonatb.malscan.controller;

import com.simonatb.malscan.configuration.SpringContext;
import com.simonatb.malscan.entity.User;
import com.simonatb.malscan.entity.VerificationToken;
import com.simonatb.malscan.repository.TokenRepository;
import com.simonatb.malscan.repository.UserRepository;
import com.simonatb.malscan.service.EmailService;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import javafx.stage.Stage;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class RegisterController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenRepository tokenRepository;
    private final EmailService emailService;

    @FXML
    private TextField nameField;
    @FXML private TextField emailField;
    @FXML private PasswordField passwordField;
    @FXML private Label errorLabel;
    @FXML private Button registerButton;

    @FXML
    public void onRegister() {
        String name = nameField.getText().trim();
        String email = emailField.getText().trim();
        String password = passwordField.getText();

        if (name.isBlank() || email.isBlank() || password.isBlank()) {
            showError("All fields are required.");
            return;
        }

        if (!email.contains("@")) {
            showError("Please enter a valid email.");
            return;
        }

        if (password.length() < 6) {
            showError("Password must be at least 6 characters.");
            return;
        }

        if (userRepository.findByEmail(email).isPresent()) {
            showError("Email already in use.");
            return;
        }

        User user = User.builder()
            .name(name)
            .email(email)
            .password(passwordEncoder.encode(password))
            .role(User.Role.ROLE_USER)
            .enabled(false)
            .build();
        userRepository.save(user);

        String tokenValue = UUID.randomUUID().toString();
        VerificationToken token = VerificationToken.builder()
            .token(tokenValue)
            .user(user)
            .expiresAt(LocalDateTime.now().plusHours(24))
            .build();
        tokenRepository.save(token);

        emailService.sendVerificationEmail(email, tokenValue);

        showSuccess();
    }

    private void showError(String message) {
        errorLabel.setText(message);
        errorLabel.setStyle("-fx-text-fill: red;");
    }

    private void showSuccess() {
        nameField.clear();
        emailField.clear();
        passwordField.clear();

        errorLabel.setText("✓ Account created! Check your email to verify.");
        errorLabel.setStyle("-fx-text-fill: green;");
        registerButton.setDisable(true);
    }

    @FXML
    public void onLoginLink() {
        try {
            FXMLLoader loader = new FXMLLoader();
            loader.setLocation(getClass().getResource("/fxml/login.fxml"));
            loader.setControllerFactory(SpringContext.getContext()::getBean);
            Stage stage = (Stage) emailField.getScene().getWindow();
            stage.setScene(new Scene(loader.load()));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}