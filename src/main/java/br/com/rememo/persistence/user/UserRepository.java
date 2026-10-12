package br.com.rememo.persistence.user;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends JpaRepository<UserEntity, Long> {

    Optional<UserEntity> findByIdentityProviderId(String identityProviderId);

    Optional<UserEntity> findByUuid(UUID uuid);
}
