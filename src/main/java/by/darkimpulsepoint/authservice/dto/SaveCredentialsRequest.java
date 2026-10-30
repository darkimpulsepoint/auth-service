package by.darkimpulsepoint.authservice.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;

public record SaveCredentialsRequest(
        @NotBlank(message = "login must not be blank")
        @Size(min = 3, max = 100, message = "login must be between 3 and 100 characters")
        @Pattern(regexp = "[A-Za-z0-9._@-]+", message = "login may contain only letters, digits and . _ @ -")
        String login,

        @NotBlank(message = "password must not be blank")
        @Size(min = 8, max = 72, message = "password must be between 8 and 72 characters")
        String password,

        @NotNull(message = "userId must not be null")
        @Positive(message = "userId must be positive")
        Long userId) {
}
