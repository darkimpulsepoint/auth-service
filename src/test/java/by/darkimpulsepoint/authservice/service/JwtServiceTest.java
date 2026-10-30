package by.darkimpulsepoint.authservice.service;

import by.darkimpulsepoint.authservice.config.SecurityConfig;
import by.darkimpulsepoint.authservice.entity.Credential;
import by.darkimpulsepoint.authservice.entity.Role;
import by.darkimpulsepoint.authservice.exception.InvalidTokenException;
import by.darkimpulsepoint.authservice.security.JwtClaimNames;
import by.darkimpulsepoint.authservice.security.JwtProperties;
import by.darkimpulsepoint.authservice.security.TokenType;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;

import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtServiceTest {

    private static final String SECRET = "unit-test-secret-key-which-is-long-enough";

    private final JwtService jwtService = jwtService(SECRET, Duration.ofMinutes(15));

    @Test
    void accessToken_containsUserIdRoleAndType() {
        String token = jwtService.generateAccessToken(credential(Role.USER, 42L));

        Jwt jwt = jwtService.parse(token, TokenType.ACCESS);

        assertThat(jwt.getSubject()).isEqualTo("ivan");
        assertThat(jwt.getClaimAsString("iss")).isEqualTo("auth-service");
        assertThat(jwt.<Number>getClaim(JwtClaimNames.USER_ID).longValue()).isEqualTo(42L);
        assertThat(jwt.getClaimAsString(JwtClaimNames.ROLE)).isEqualTo("USER");
        assertThat(jwt.getClaimAsString(JwtClaimNames.TOKEN_TYPE)).isEqualTo("access");
        assertThat(jwt.getId()).isNotBlank();
        assertThat(Duration.between(jwt.getIssuedAt(), jwt.getExpiresAt())).isEqualTo(Duration.ofMinutes(15));
    }

    @Test
    void adminToken_withoutUserId_hasNoUserIdClaim() {
        String token = jwtService.generateAccessToken(credential(Role.ADMIN, null));

        Jwt jwt = jwtService.parse(token, TokenType.ACCESS);

        assertThat(jwt.hasClaim(JwtClaimNames.USER_ID)).isFalse();
        assertThat(jwt.getClaimAsString(JwtClaimNames.ROLE)).isEqualTo("ADMIN");
    }

    @Test
    void parse_withWrongType_throws() {
        String refresh = jwtService.generateRefreshToken(credential(Role.USER, 1L));
        String access = jwtService.generateAccessToken(credential(Role.USER, 1L));

        assertThatThrownBy(() -> jwtService.parse(refresh, TokenType.ACCESS))
                .isInstanceOf(InvalidTokenException.class);
        assertThatThrownBy(() -> jwtService.parse(access, TokenType.REFRESH))
                .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void parse_tokenSignedWithAnotherSecret_throws() {
        String foreign = jwtService("another-secret-key-which-is-long-enough", Duration.ofMinutes(15))
                .generateAccessToken(credential(Role.ADMIN, null));

        assertThatThrownBy(() -> jwtService.parse(foreign, TokenType.ACCESS))
                .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void parse_expiredToken_throws() {
        // the default validator allows 60s of clock skew, so the token expired well before that
        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("auth-service")
                .subject("ivan")
                .issuedAt(now.minus(Duration.ofMinutes(20)))
                .expiresAt(now.minus(Duration.ofMinutes(5)))
                .claim(JwtClaimNames.ROLE, "USER")
                .claim(JwtClaimNames.TOKEN_TYPE, "access")
                .build();
        String expired = securityConfig(SECRET, Duration.ofMinutes(15)).jwtEncoder()
                .encode(JwtEncoderParameters.from(JwsHeader.with(MacAlgorithm.HS256).build(), claims))
                .getTokenValue();

        assertThatThrownBy(() -> jwtService.parse(expired, TokenType.ACCESS))
                .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void parse_garbage_throws() {
        assertThatThrownBy(() -> jwtService.parse("not-a-jwt", TokenType.ACCESS))
                .isInstanceOf(InvalidTokenException.class);
    }

    static JwtService jwtService(String secret, Duration accessTtl) {
        JwtProperties properties = properties(secret, accessTtl);
        SecurityConfig config = new SecurityConfig(properties, null);
        return new JwtService(config.jwtEncoder(), config.jwtDecoder(), properties);
    }

    private static SecurityConfig securityConfig(String secret, Duration accessTtl) {
        return new SecurityConfig(properties(secret, accessTtl), null);
    }

    private static JwtProperties properties(String secret, Duration accessTtl) {
        return new JwtProperties(secret, "auth-service", accessTtl, Duration.ofDays(7));
    }

    static Credential credential(Role role, Long userId) {
        Credential credential = new Credential();
        credential.setLogin("ivan");
        credential.setPasswordHash("hash");
        credential.setRole(role);
        credential.setUserId(userId);
        return credential;
    }
}
