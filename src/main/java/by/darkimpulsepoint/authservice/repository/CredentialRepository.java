package by.darkimpulsepoint.authservice.repository;

import by.darkimpulsepoint.authservice.entity.Credential;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface CredentialRepository extends JpaRepository<Credential, Long> {

    Optional<Credential> findByLogin(String login);

    boolean existsByLogin(String login);

    boolean existsByUserId(Long userId);
}
