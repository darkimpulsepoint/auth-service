package by.darkimpulsepoint.authservice.security;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;

@Validated
@ConfigurationProperties(prefix = "security.jwt")
public record JwtProperties(
        @NotBlank
        @Size(min = 32, message = "secret must be at least 32 characters for HS256")
        String secret,

        @NotBlank
        String issuer,

        @NotNull
        Duration accessTokenTtl,

        @NotNull
        Duration refreshTokenTtl) {
}
