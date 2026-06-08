package com.simonatb.malscan.controller;

import com.simonatb.malscan.configuration.SpringContext;
import com.simonatb.malscan.entity.User;
import com.simonatb.malscan.repository.UserRepository;
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

@Component
@RequiredArgsConstructor
public class LoginController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @FXML private TextField emailField;
    @FXML private PasswordField passwordField;
    @FXML private Label errorLabel;
    @FXML private Button loginButton;

    @FXML
    public void onLogin() {
        String email = emailField.getText().trim();
        String password = passwordField.getText();

        if (email.isBlank() || password.isBlank()) {
            showError("All fields are required.");
            return;
        }

        User user = userRepository.findByEmail(email).orElse(null);

        if (user == null || !passwordEncoder.matches(password, user.getPassword())) {
            showError("Invalid email or password.");
            return;
        }

        if (!user.isEnabled()) {
            showError("Please verify your email before logging in.");
            return;
        }

        goToDashboard(user);
    }

    private void showError(String message) {
        errorLabel.setText(message);
        errorLabel.setStyle("-fx-text-fill: red;");
    }

    private void goToDashboard(User user) {
        try {
            FXMLLoader loader = new FXMLLoader(
                getClass().getResource("/fxml/dashboard.fxml"));
            loader.setControllerFactory(SpringContext.getContext()::getBean);
            Stage stage = (Stage) emailField.getScene().getWindow();
            stage.setScene(new Scene(loader.load()));
            stage.setTitle("MalScan - " + user.getName());
        } catch (Exception e) {
            e.printStackTrace();
            showError("Failed to load dashboard: " + e.getMessage());
        }
    }

    @FXML
    public void onSignupLink() {
        try {
            FXMLLoader loader = new FXMLLoader();
            loader.setLocation(getClass().getResource("/fxml/register.fxml"));
            loader.setControllerFactory(SpringContext.getContext()::getBean);
            Stage stage = (Stage) emailField.getScene().getWindow();
            stage.setScene(new Scene(loader.load()));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}