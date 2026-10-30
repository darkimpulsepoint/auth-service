package by.darkimpulsepoint.authservice.security;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "security.admin")
public record AdminProperties(String login, String password) {
}
