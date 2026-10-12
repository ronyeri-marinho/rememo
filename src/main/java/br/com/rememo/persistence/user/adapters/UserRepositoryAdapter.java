package br.com.rememo.persistence.user.adapters;

import br.com.rememo.domain.user.User;
import br.com.rememo.persistence.user.UserRepository;
import br.com.rememo.persistence.user.mappers.UserPersistenceMapper;
import br.com.rememo.persistence.user.ports.UserRepositoryPort;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.UUID;

@Component
public class UserRepositoryAdapter implements UserRepositoryPort {

    private final UserRepository userRepository;

    public UserRepositoryAdapter(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public User save(User user) {
        return UserPersistenceMapper
                .toDomain(this.userRepository.save(UserPersistenceMapper.toEntity(user)));
    }

    @Override
    public Optional<User> findByIdentityProviderId(String identityProviderId) {
        return this.userRepository.findByIdentityProviderId(identityProviderId)
                .map(UserPersistenceMapper::toDomain);
    }

    @Override
    public Optional<User> findByUuid(UUID uuid) {
        return this.userRepository.findByUuid(uuid)
                .map(UserPersistenceMapper::toDomain);
    }
}
