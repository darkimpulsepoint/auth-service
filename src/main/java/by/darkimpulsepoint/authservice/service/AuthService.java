package by.darkimpulsepoint.authservice.service;

import by.darkimpulsepoint.authservice.dto.CredentialResponse;
import by.darkimpulsepoint.authservice.dto.LoginRequest;
import by.darkimpulsepoint.authservice.dto.RefreshTokenRequest;
import by.darkimpulsepoint.authservice.dto.SaveCredentialsRequest;
import by.darkimpulsepoint.authservice.dto.TokenResponse;
import by.darkimpulsepoint.authservice.dto.TokenValidationResponse;
import by.darkimpulsepoint.authservice.entity.Credential;
import by.darkimpulsepoint.authservice.entity.Role;
import by.darkimpulsepoint.authservice.exception.DuplicateEntityException;
import by.darkimpulsepoint.authservice.exception.InvalidCredentialsException;
import by.darkimpulsepoint.authservice.exception.InvalidTokenException;
import by.darkimpulsepoint.authservice.repository.CredentialRepository;
import by.darkimpulsepoint.authservice.security.JwtClaimNames;
import by.darkimpulsepoint.authservice.security.JwtProperties;
import by.darkimpulsepoint.authservice.security.TokenType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
public class AuthService {

    private static final String TOKEN_TYPE = "Bearer";
    private static final String INVALID_CREDENTIALS = "Invalid login or password";

    private final CredentialRepository credentialRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final JwtProperties jwtProperties;
    private final String dummyHash;

    public AuthService(CredentialRepository credentialRepository,
                       PasswordEncoder passwordEncoder,
                       JwtService jwtService,
                       JwtProperties jwtProperties) {
        this.credentialRepository = credentialRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.jwtProperties = jwtProperties;
        this.dummyHash = passwordEncoder.encode("dummy-password");
    }

    @Transactional
    public CredentialResponse saveCredentials(SaveCredentialsRequest request) {
        if (credentialRepository.existsByLogin(request.login())) {
            throw new DuplicateEntityException("Login " + request.login() + " is already taken");
        }
        if (credentialRepository.existsByUserId(request.userId())) {
            throw new DuplicateEntityException("Credentials for user " + request.userId() + " already exist");
        }
        Credential saved = credentialRepository.save(
                newCredential(request.login(), request.password(), Role.USER, request.userId()));
        return toResponse(saved);
    }

    @Transactional
    public CredentialResponse createAdminIfAbsent(String login, String password) {
        Optional<Credential> existing = credentialRepository.findByLogin(login);
        return toResponse(existing.orElseGet(() ->
                credentialRepository.save(newCredential(login, password, Role.ADMIN, null))));
    }

    @Transactional(readOnly = true)
    public TokenResponse login(LoginRequest request) {
        Optional<Credential> credential = credentialRepository.findByLogin(request.login());
        if (credential.isEmpty()) {
            passwordEncoder.matches(request.password(), dummyHash);
            throw new InvalidCredentialsException(INVALID_CREDENTIALS);
        }
        if (!passwordEncoder.matches(request.password(), credential.get().getPasswordHash())) {
            throw new InvalidCredentialsException(INVALID_CREDENTIALS);
        }
        return issueTokens(credential.get());
    }

    @Transactional(readOnly = true)
    public TokenResponse refresh(RefreshTokenRequest request) {
        Jwt refreshToken = jwtService.parse(request.refreshToken(), TokenType.REFRESH);
        Credential credential = credentialRepository.findByLogin(refreshToken.getSubject())
                .orElseThrow(() -> new InvalidTokenException("User of the refresh token no longer exists"));
        return issueTokens(credential);
    }

    public TokenValidationResponse validate(String token) {
        try {
            Jwt jwt = jwtService.parse(token, TokenType.ACCESS);
            Number userId = jwt.getClaim(JwtClaimNames.USER_ID);
            return new TokenValidationResponse(
                    true,
                    jwt.getSubject(),
                    userId != null ? userId.longValue() : null,
                    Role.valueOf(jwt.getClaimAsString(JwtClaimNames.ROLE)),
                    jwt.getExpiresAt());
        } catch (InvalidTokenException ex) {
            return TokenValidationResponse.invalid();
        }
    }

    private TokenResponse issueTokens(Credential credential) {
        return new TokenResponse(
                jwtService.generateAccessToken(credential),
                jwtService.generateRefreshToken(credential),
                TOKEN_TYPE,
                jwtProperties.accessTokenTtl().toSeconds());
    }

    private Credential newCredential(String login, String password, Role role, Long userId) {
        Credential credential = new Credential();
        credential.setLogin(login);
        credential.setPasswordHash(passwordEncoder.encode(password));
        credential.setRole(role);
        credential.setUserId(userId);
        return credential;
    }

    private CredentialResponse toResponse(Credential credential) {
        return new CredentialResponse(credential.getId(), credential.getLogin(), credential.getUserId(),
                credential.getRole(), credential.getCreatedAt());
    }
}
