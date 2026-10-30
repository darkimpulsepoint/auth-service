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
import by.darkimpulsepoint.authservice.security.JwtProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Duration;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AuthServiceTest {

    private static final String PASSWORD = "password123";

    private final CredentialRepository repository = mock(CredentialRepository.class);
    // low strength keeps the tests fast, the algorithm is the same
    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder(4);
    private final JwtService jwtService =
            JwtServiceTest.jwtService("unit-test-secret-key-which-is-long-enough", Duration.ofMinutes(15));
    private AuthService authService;

    @BeforeEach
    void setUp() {
        JwtProperties properties = new JwtProperties("unused-secret-unused-secret-unused", "auth-service",
                Duration.ofMinutes(15), Duration.ofDays(7));
        authService = new AuthService(repository, passwordEncoder, jwtService, properties);
        when(repository.save(any(Credential.class))).thenAnswer(invocation -> {
            Credential credential = invocation.getArgument(0);
            credential.setId(1L);
            return credential;
        });
    }

    @Test
    void saveCredentials_storesBcryptHashWithUserRole() {
        CredentialResponse response = authService.saveCredentials(new SaveCredentialsRequest("ivan", PASSWORD, 7L));

        ArgumentCaptor<Credential> captor = ArgumentCaptor.forClass(Credential.class);
        verify(repository).save(captor.capture());
        Credential saved = captor.getValue();
        assertThat(saved.getPasswordHash()).isNotEqualTo(PASSWORD).startsWith("$2a$");
        assertThat(passwordEncoder.matches(PASSWORD, saved.getPasswordHash())).isTrue();
        assertThat(saved.getRole()).isEqualTo(Role.USER);
        assertThat(response.userId()).isEqualTo(7L);
        assertThat(response.role()).isEqualTo(Role.USER);
    }

    @Test
    void samePassword_getsDifferentHashes() {
        authService.saveCredentials(new SaveCredentialsRequest("ivan", PASSWORD, 1L));
        authService.saveCredentials(new SaveCredentialsRequest("petr", PASSWORD, 2L));

        ArgumentCaptor<Credential> captor = ArgumentCaptor.forClass(Credential.class);
        verify(repository, times(2)).save(captor.capture());
        assertThat(captor.getAllValues().get(0).getPasswordHash())
                .isNotEqualTo(captor.getAllValues().get(1).getPasswordHash());
    }

    @Test
    void saveCredentials_withTakenLogin_throws() {
        when(repository.existsByLogin("ivan")).thenReturn(true);

        assertThatThrownBy(() -> authService.saveCredentials(new SaveCredentialsRequest("ivan", PASSWORD, 7L)))
                .isInstanceOf(DuplicateEntityException.class);
        verify(repository, never()).save(any());
    }

    @Test
    void saveCredentials_forUserWithCredentials_throws() {
        when(repository.existsByUserId(7L)).thenReturn(true);

        assertThatThrownBy(() -> authService.saveCredentials(new SaveCredentialsRequest("ivan", PASSWORD, 7L)))
                .isInstanceOf(DuplicateEntityException.class);
        verify(repository, never()).save(any());
    }

    @Test
    void login_withValidPassword_returnsTokenPair() {
        when(repository.findByLogin("ivan")).thenReturn(Optional.of(stored(Role.USER, 7L)));

        TokenResponse tokens = authService.login(new LoginRequest("ivan", PASSWORD));

        assertThat(tokens.tokenType()).isEqualTo("Bearer");
        assertThat(tokens.expiresIn()).isEqualTo(900);
        TokenValidationResponse validation = authService.validate(tokens.accessToken());
        assertThat(validation.valid()).isTrue();
        assertThat(validation.userId()).isEqualTo(7L);
        assertThat(validation.role()).isEqualTo(Role.USER);
        assertThat(authService.validate(tokens.refreshToken()).valid()).isFalse();
    }

    @Test
    void login_withWrongPassword_throws() {
        when(repository.findByLogin("ivan")).thenReturn(Optional.of(stored(Role.USER, 7L)));

        assertThatThrownBy(() -> authService.login(new LoginRequest("ivan", "wrong-password")))
                .isInstanceOf(InvalidCredentialsException.class)
                .hasMessage("Invalid login or password");
    }

    @Test
    void login_withUnknownLogin_throwsSameError() {
        when(repository.findByLogin("ghost")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.login(new LoginRequest("ghost", PASSWORD)))
                .isInstanceOf(InvalidCredentialsException.class)
                .hasMessage("Invalid login or password");
    }

    @Test
    void refresh_reissuesTokensWithCurrentRole() {
        Credential credential = stored(Role.USER, 7L);
        when(repository.findByLogin("ivan")).thenReturn(Optional.of(credential));
        TokenResponse initial = authService.login(new LoginRequest("ivan", PASSWORD));
        credential.setRole(Role.ADMIN);

        TokenResponse refreshed = authService.refresh(new RefreshTokenRequest(initial.refreshToken()));

        assertThat(authService.validate(refreshed.accessToken()).role()).isEqualTo(Role.ADMIN);
    }

    @Test
    void refresh_withAccessToken_throws() {
        when(repository.findByLogin("ivan")).thenReturn(Optional.of(stored(Role.USER, 7L)));
        TokenResponse tokens = authService.login(new LoginRequest("ivan", PASSWORD));

        assertThatThrownBy(() -> authService.refresh(new RefreshTokenRequest(tokens.accessToken())))
                .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void refresh_whenCredentialsWereRemoved_throws() {
        when(repository.findByLogin("ivan")).thenReturn(Optional.of(stored(Role.USER, 7L)));
        TokenResponse tokens = authService.login(new LoginRequest("ivan", PASSWORD));
        when(repository.findByLogin("ivan")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.refresh(new RefreshTokenRequest(tokens.refreshToken())))
                .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void validate_withGarbage_returnsInvalid() {
        TokenValidationResponse response = authService.validate("garbage");

        assertThat(response.valid()).isFalse();
        assertThat(response.userId()).isNull();
    }

    @Test
    void createAdminIfAbsent_createsAdminOnlyOnce() {
        when(repository.findByLogin("admin")).thenReturn(Optional.empty());
        CredentialResponse created = authService.createAdminIfAbsent("admin", PASSWORD);
        assertThat(created.role()).isEqualTo(Role.ADMIN);
        assertThat(created.userId()).isNull();

        when(repository.findByLogin("admin")).thenReturn(Optional.of(stored(Role.ADMIN, null)));
        authService.createAdminIfAbsent("admin", PASSWORD);

        verify(repository, times(1)).save(any());
    }

    private Credential stored(Role role, Long userId) {
        Credential credential = JwtServiceTest.credential(role, userId);
        credential.setPasswordHash(passwordEncoder.encode(PASSWORD));
        return credential;
    }
}
