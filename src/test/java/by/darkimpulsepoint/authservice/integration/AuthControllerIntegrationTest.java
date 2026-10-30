package by.darkimpulsepoint.authservice.integration;

import by.darkimpulsepoint.authservice.dto.CredentialResponse;
import by.darkimpulsepoint.authservice.dto.LoginRequest;
import by.darkimpulsepoint.authservice.dto.RefreshTokenRequest;
import by.darkimpulsepoint.authservice.dto.SaveCredentialsRequest;
import by.darkimpulsepoint.authservice.dto.TokenResponse;
import by.darkimpulsepoint.authservice.dto.TokenValidationResponse;
import by.darkimpulsepoint.authservice.dto.ValidateTokenRequest;
import by.darkimpulsepoint.authservice.entity.Credential;
import by.darkimpulsepoint.authservice.entity.Role;
import by.darkimpulsepoint.authservice.exception.ApiError;
import by.darkimpulsepoint.authservice.repository.CredentialRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.client.RestClient;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AuthControllerIntegrationTest {

    private static final String AUTH = "/api/v1/auth";
    private static final String ADMIN_LOGIN = "admin";
    private static final String ADMIN_PASSWORD = "admin-password";

    private static final PostgreSQLContainer POSTGRES =
            new PostgreSQLContainer(DockerImageName.parse("postgres:18"));

    static {
        POSTGRES.start();
    }

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("security.jwt.secret", () -> "integration-test-secret-key-for-hs256");
        registry.add("security.admin.login", () -> ADMIN_LOGIN);
        registry.add("security.admin.password", () -> ADMIN_PASSWORD);
    }

    @Value("${local.server.port}")
    private int port;

    @Autowired
    private CredentialRepository credentialRepository;

    private RestClient rest;

    @BeforeEach
    void setUp() {
        rest = RestClient.builder()
                .baseUrl("http://localhost:" + port)
                .defaultStatusHandler(status -> true, (request, response) -> {
                })
                .build();
        credentialRepository.findAll().stream()
                .filter(credential -> credential.getRole() == Role.USER)
                .forEach(credentialRepository::delete);
    }

    @Test
    void saveCredentials_returns201AndStoresBcryptHash() {
        ResponseEntity<CredentialResponse> response = save("ivan", "password123", 10L);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(response.getBody().login()).isEqualTo("ivan");
        assertThat(response.getBody().userId()).isEqualTo(10L);
        assertThat(response.getBody().role()).isEqualTo(Role.USER);
        Credential stored = credentialRepository.findByLogin("ivan").orElseThrow();
        assertThat(stored.getPasswordHash()).isNotEqualTo("password123").startsWith("$2a$");
    }

    @Test
    void saveCredentials_withTakenLogin_returns409() {
        save("ivan", "password123", 10L);

        ResponseEntity<ApiError> response = rest.post().uri(AUTH + "/credentials")
                .body(new SaveCredentialsRequest("ivan", "password123", 11L))
                .retrieve().toEntity(ApiError.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        assertThat(response.getBody().message()).contains("ivan");
    }

    @Test
    void saveCredentials_withInvalidBody_returns400() {
        ResponseEntity<ApiError> response = rest.post().uri(AUTH + "/credentials")
                .body(new SaveCredentialsRequest("i", "short", null))
                .retrieve().toEntity(ApiError.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody().validationErrors()).containsKeys("login", "password", "userId");
    }

    @Test
    void login_validateAndRefresh_fullFlow() {
        save("ivan", "password123", 10L);

        TokenResponse tokens = login("ivan", "password123").getBody();
        assertThat(tokens.accessToken()).isNotBlank();
        assertThat(tokens.refreshToken()).isNotBlank();
        assertThat(tokens.tokenType()).isEqualTo("Bearer");

        TokenValidationResponse validation = validate(tokens.accessToken());
        assertThat(validation.valid()).isTrue();
        assertThat(validation.login()).isEqualTo("ivan");
        assertThat(validation.userId()).isEqualTo(10L);
        assertThat(validation.role()).isEqualTo(Role.USER);
        assertThat(validation.expiresAt()).isNotNull();

        ResponseEntity<TokenResponse> refreshed = rest.post().uri(AUTH + "/refresh")
                .body(new RefreshTokenRequest(tokens.refreshToken()))
                .retrieve().toEntity(TokenResponse.class);
        assertThat(refreshed.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(validate(refreshed.getBody().accessToken()).userId()).isEqualTo(10L);
    }

    @Test
    void login_asInitialAdmin_returnsAdminToken() {
        TokenResponse tokens = login(ADMIN_LOGIN, ADMIN_PASSWORD).getBody();

        TokenValidationResponse validation = validate(tokens.accessToken());
        assertThat(validation.role()).isEqualTo(Role.ADMIN);
        assertThat(validation.userId()).isNull();
    }

    @Test
    void login_withWrongPassword_returns401() {
        save("ivan", "password123", 10L);

        ResponseEntity<ApiError> response = rest.post().uri(AUTH + "/login")
                .body(new LoginRequest("ivan", "wrong-password"))
                .retrieve().toEntity(ApiError.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE)).isEqualTo("Bearer");
        assertThat(response.getBody().message()).isEqualTo("Invalid login or password");
    }

    @Test
    void refresh_withAccessToken_returns401() {
        save("ivan", "password123", 10L);
        TokenResponse tokens = login("ivan", "password123").getBody();

        ResponseEntity<ApiError> response = rest.post().uri(AUTH + "/refresh")
                .body(new RefreshTokenRequest(tokens.accessToken()))
                .retrieve().toEntity(ApiError.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void validate_withInvalidToken_returnsInvalid() {
        TokenValidationResponse response = validate("not-a-token");

        assertThat(response.valid()).isFalse();
        assertThat(response.userId()).isNull();
    }

    @Test
    void unknownEndpoint_withoutAuthentication_returns401() {
        ResponseEntity<ApiError> response = rest.get().uri("/api/v1/something")
                .retrieve().toEntity(ApiError.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getBody().status()).isEqualTo(401);
    }

    private ResponseEntity<CredentialResponse> save(String login, String password, Long userId) {
        return rest.post().uri(AUTH + "/credentials")
                .body(new SaveCredentialsRequest(login, password, userId))
                .retrieve().toEntity(CredentialResponse.class);
    }

    private ResponseEntity<TokenResponse> login(String login, String password) {
        ResponseEntity<TokenResponse> response = rest.post().uri(AUTH + "/login")
                .body(new LoginRequest(login, password))
                .retrieve().toEntity(TokenResponse.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        return response;
    }

    private TokenValidationResponse validate(String token) {
        ResponseEntity<TokenValidationResponse> response = rest.post().uri(AUTH + "/validate")
                .body(new ValidateTokenRequest(token))
                .retrieve().toEntity(TokenValidationResponse.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        return response.getBody();
    }
}
