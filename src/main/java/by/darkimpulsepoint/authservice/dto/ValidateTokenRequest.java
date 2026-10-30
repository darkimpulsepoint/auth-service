package by.darkimpulsepoint.authservice.dto;

import jakarta.validation.constraints.NotBlank;

public record ValidateTokenRequest(
        @NotBlank(message = "token must not be blank")
        String token) {
}
