package br.com.rememo.persistence.user.ports;

import br.com.rememo.domain.user.User;

import java.util.Optional;
import java.util.UUID;

public interface UserRepositoryPort {

    User save(User user);

    Optional<User> findByIdentityProviderId(String identityProviderId);

    Optional<User> findByUuid(UUID uuid);
}
