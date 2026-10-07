package br.com.rememo.application;

import br.com.rememo.application.transport.SessionUserDTO;
import br.com.rememo.application.usecase.SynchronizeUserUseCase;
import br.com.rememo.domain.User;
import br.com.rememo.persistence.user.ports.UserRepositoryPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
public class SynchronizeUserService implements SynchronizeUserUseCase {
    private static final Logger LOGGER = LoggerFactory.getLogger(SynchronizeUserService.class);
    private final UserRepositoryPort userRepositoryPort;

    public SynchronizeUserService(UserRepositoryPort userRepositoryPort) {
        this.userRepositoryPort = userRepositoryPort;
    }

    @Transactional
    public User synchronizeUser(SessionUserDTO sessionUser) {
        LOGGER.debug("Starting user sync...");
        Optional<User> userAsOptional = this.userRepositoryPort
                .findByIdentityProviderId(sessionUser.identityProviderId());

        return userAsOptional.isEmpty() ?
                this.create(sessionUser) :
                this.updateCurrentUser(sessionUser, userAsOptional.get());
    }

    private User create(SessionUserDTO sessionUser) {
        User user = User.create(
                sessionUser.identityProviderId(),
                sessionUser.firstName(),
                sessionUser.lastName(),
                sessionUser.email()
        );

        return this.userRepositoryPort.save(user);
    }

    private User updateCurrentUser(SessionUserDTO sessionUser, User user) {
        boolean hasFirstNameChanged = user.updateFirstName(sessionUser.firstName());
        boolean hasLastNameChanged = user.updateLastName(sessionUser.lastName());
        boolean hasEmailChanged = user.updateEmail(sessionUser.email());

        if (hasFirstNameChanged || hasLastNameChanged || hasEmailChanged) {
            LOGGER.debug("User information has updates. userId: {}", user.getUuid());
            user.markUpdated();
            return this.userRepositoryPort.save(user);
        }

        return user;
    }
}
