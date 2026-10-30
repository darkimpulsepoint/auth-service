package by.darkimpulsepoint.authservice.dto;

import by.darkimpulsepoint.authservice.entity.Role;

import java.time.Instant;

public record CredentialResponse(
        Long id,
        String login,
        Long userId,
        Role role,
        Instant createdAt) {
}
