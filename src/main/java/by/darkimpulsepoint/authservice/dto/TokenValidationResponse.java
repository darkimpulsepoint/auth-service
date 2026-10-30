package by.darkimpulsepoint.authservice.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import by.darkimpulsepoint.authservice.entity.Role;

import java.time.Instant;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record TokenValidationResponse(
        boolean valid,
        String login,
        Long userId,
        Role role,
        Instant expiresAt) {

    public static TokenValidationResponse invalid() {
        return new TokenValidationResponse(false, null, null, null, null);
    }
}
