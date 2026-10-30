package by.darkimpulsepoint.authservice.config;

import by.darkimpulsepoint.authservice.security.AdminProperties;
import by.darkimpulsepoint.authservice.service.AuthService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Slf4j
@Component
@RequiredArgsConstructor
public class AdminInitializer implements ApplicationRunner {

    private final AdminProperties adminProperties;
    private final AuthService authService;

    @Override
    public void run(ApplicationArguments args) {
        if (!StringUtils.hasText(adminProperties.login()) || !StringUtils.hasText(adminProperties.password())) {
            log.info("Initial admin is not configured, skipping");
            return;
        }
        authService.createAdminIfAbsent(adminProperties.login(), adminProperties.password());
        log.info("Initial admin '{}' is present", adminProperties.login());
    }
}
