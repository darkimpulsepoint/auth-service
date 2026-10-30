package by.darkimpulsepoint.authservice.controller;

import by.darkimpulsepoint.authservice.dto.CredentialResponse;
import by.darkimpulsepoint.authservice.dto.LoginRequest;
import by.darkimpulsepoint.authservice.dto.RefreshTokenRequest;
import by.darkimpulsepoint.authservice.dto.SaveCredentialsRequest;
import by.darkimpulsepoint.authservice.dto.TokenResponse;
import by.darkimpulsepoint.authservice.dto.TokenValidationResponse;
import by.darkimpulsepoint.authservice.dto.ValidateTokenRequest;
import by.darkimpulsepoint.authservice.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/credentials")
    public ResponseEntity<CredentialResponse> saveCredentials(@Valid @RequestBody SaveCredentialsRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.saveCredentials(request));
    }

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(@Valid @RequestBody RefreshTokenRequest request) {
        return ResponseEntity.ok(authService.refresh(request));
    }

    @PostMapping("/validate")
    public ResponseEntity<TokenValidationResponse> validate(@Valid @RequestBody ValidateTokenRequest request) {
        return ResponseEntity.ok(authService.validate(request.token()));
    }
}
