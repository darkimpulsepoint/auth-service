package by.darkimpulsepoint.authservice.dto;

import jakarta.validation.constraints.NotBlank;

public record LoginRequest(
        @NotBlank(message = "login must not be blank")
        String login,

        @NotBlank(message = "password must not be blank")
        String password) {
}
