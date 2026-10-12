package br.com.rememo.application.user;

import br.com.rememo.application.user.transport.UserInSessionDTO;
import br.com.rememo.application.user.usecase.SynchronizeUserUseCase;
import br.com.rememo.domain.user.User;
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
    public User synchronizeUser(UserInSessionDTO sessionUser) {
        Optional<User> userAsOptional = this.userRepositoryPort
                .findByIdentityProviderId(sessionUser.identityProviderId());

        return userAsOptional.isEmpty() ?
                this.create(sessionUser) :
                this.updateCurrentUser(sessionUser, userAsOptional.get());
    }

    private User create(UserInSessionDTO sessionUser) {
        User user = User.create(
                sessionUser.identityProviderId(),
                sessionUser.firstName(),
                sessionUser.lastName(),
                sessionUser.email()
        );

        User newUser = this.userRepositoryPort.save(user);

        LOGGER.debug(
                "User created successfully. userId={}",
                newUser.getUuid()
        );

        return newUser;
    }

    private User updateCurrentUser(UserInSessionDTO sessionUser, User user) {
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
