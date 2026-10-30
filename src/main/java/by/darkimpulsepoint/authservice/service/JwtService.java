package by.darkimpulsepoint.authservice.service;

import by.darkimpulsepoint.authservice.entity.Credential;
import by.darkimpulsepoint.authservice.entity.Role;
import by.darkimpulsepoint.authservice.exception.InvalidTokenException;
import by.darkimpulsepoint.authservice.security.JwtClaimNames;
import by.darkimpulsepoint.authservice.security.JwtProperties;
import by.darkimpulsepoint.authservice.security.TokenType;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class JwtService {

    private final JwtEncoder jwtEncoder;
    private final JwtDecoder jwtDecoder;
    private final JwtProperties jwtProperties;

    public String generateAccessToken(Credential credential) {
        return generate(credential, TokenType.ACCESS, jwtProperties.accessTokenTtl());
    }

    public String generateRefreshToken(Credential credential) {
        return generate(credential, TokenType.REFRESH, jwtProperties.refreshTokenTtl());
    }

    public Jwt parse(String token, TokenType expectedType) {
        Jwt jwt;
        try {
            jwt = jwtDecoder.decode(token);
        } catch (JwtException ex) {
            throw new InvalidTokenException("Invalid or expired token", ex);
        }
        if (!expectedType.claimValue().equals(jwt.getClaimAsString(JwtClaimNames.TOKEN_TYPE))) {
            throw new InvalidTokenException("Token is not a " + expectedType.claimValue() + " token");
        }
        String role = jwt.getClaimAsString(JwtClaimNames.ROLE);
        if (Arrays.stream(Role.values()).noneMatch(known -> known.name().equals(role))) {
            throw new InvalidTokenException("Token has no valid role");
        }
        return jwt;
    }

    private String generate(Credential credential, TokenType type, Duration ttl) {
        Instant now = Instant.now();
        JwtClaimsSet.Builder claims = JwtClaimsSet.builder()
                .id(UUID.randomUUID().toString())
                .issuer(jwtProperties.issuer())
                .subject(credential.getLogin())
                .issuedAt(now)
                .expiresAt(now.plus(ttl))
                .claim(JwtClaimNames.ROLE, credential.getRole().name())
                .claim(JwtClaimNames.TOKEN_TYPE, type.claimValue());
        if (credential.getUserId() != null) {
            claims.claim(JwtClaimNames.USER_ID, credential.getUserId());
        }
        JwsHeader header = JwsHeader.with(MacAlgorithm.HS256).build();
        return jwtEncoder.encode(JwtEncoderParameters.from(header, claims.build())).getTokenValue();
    }
}
