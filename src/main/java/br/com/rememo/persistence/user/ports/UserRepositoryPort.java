package br.com.rememo.persistence.user.ports;

import br.com.rememo.domain.User;

import java.util.Optional;

public interface UserRepositoryPort {

    User save(User user);

    Optional<User> findByIdentityProviderId(String identityProviderId);
}
