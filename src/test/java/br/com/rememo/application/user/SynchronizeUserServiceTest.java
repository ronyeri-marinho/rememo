package br.com.rememo.application.user;

import br.com.rememo.application.user.transport.UserInSessionDTO;
import br.com.rememo.domain.user.User;
import br.com.rememo.persistence.user.ports.UserRepositoryPort;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SynchronizeUserServiceTest {

    @Mock
    private UserRepositoryPort userRepositoryPort;

    @InjectMocks
    private SynchronizeUserService synchronizeUserService;

    @Test
    @DisplayName("Should create a new user")
    void shouldCreateNewUser() {
        UserInSessionDTO userInSessionDTO = this.setupSessionUserDTO();

        User createdUser = new User();

        when(this.userRepositoryPort.findByIdentityProviderId(userInSessionDTO.identityProviderId()))
                .thenReturn(Optional.empty());

        when(this.userRepositoryPort.save(any(User.class))).thenReturn(createdUser);

        this.synchronizeUserService.synchronizeUser(userInSessionDTO);

        ArgumentCaptor<User> userArgumentCaptor = ArgumentCaptor.forClass(User.class);
        verify(this.userRepositoryPort).save(userArgumentCaptor.capture());
        User user = userArgumentCaptor.getValue();

        createdUser.setUuid(user.getUuid());

        assertNotNull(user);
        assertNotNull(user.getUuid());
        assertEquals(userInSessionDTO.identityProviderId(), user.getIdentityProviderId());
        assertEquals(userInSessionDTO.firstName(), user.getFirstName());
        assertEquals(userInSessionDTO.lastName(), user.getLastName());
        assertEquals(userInSessionDTO.email(), user.getEmail());
        assertNotNull(user.getCreatedAt());
        assertNotNull(user.getUpdatedAt());
    }

    @Test
    @DisplayName("Should update a user that already exists")
    void shouldUpdateUserThatAlreadyExists() {
        UserInSessionDTO userInSessionDTO = this.setupSessionUserDTO();

        User currentUser = User.create(
                "eac5b18d-4912-4216-ba61-8b2e379de594",
                "Jane",
                "Doe",
                "jane.doe@example.com"
        );

        when(this.userRepositoryPort.findByIdentityProviderId(userInSessionDTO.identityProviderId()))
                .thenReturn(Optional.of(currentUser));

        this.synchronizeUserService.synchronizeUser(userInSessionDTO);

        ArgumentCaptor<User> userArgumentCaptor = ArgumentCaptor.forClass(User.class);
        verify(this.userRepositoryPort).save(userArgumentCaptor.capture());
        User user = userArgumentCaptor.getValue();

        assertNotNull(user);
        assertEquals(currentUser.getUuid(), user.getUuid());
        assertEquals(currentUser.getIdentityProviderId(), user.getIdentityProviderId());
        assertEquals(currentUser.getFirstName(), user.getFirstName());
        assertEquals(currentUser.getLastName(), user.getLastName());
        assertEquals(currentUser.getEmail(), user.getEmail());
        assertNotNull(user.getCreatedAt());
        assertNotNull(user.getUpdatedAt());
    }

    @Test
    @DisplayName("Should be idempotent")
    void shouldBeIdempotent() {
        UserInSessionDTO userInSessionDTO = this.setupSessionUserDTO();

        User currentUser = User.create(
                userInSessionDTO.identityProviderId(),
                userInSessionDTO.firstName(),
                userInSessionDTO.lastName(),
                userInSessionDTO.email()
        );

        when(this.userRepositoryPort.findByIdentityProviderId(userInSessionDTO.identityProviderId()))
                .thenReturn(Optional.of(currentUser));

        User user = this.synchronizeUserService.synchronizeUser(userInSessionDTO);

        assertNotNull(user);
        assertEquals(currentUser.getUuid(), user.getUuid());
        assertEquals(currentUser.getIdentityProviderId(), user.getIdentityProviderId());
        assertEquals(currentUser.getFirstName(), user.getFirstName());
        assertEquals(currentUser.getLastName(), user.getLastName());
        assertEquals(currentUser.getEmail(), user.getEmail());
        assertNotNull(user.getCreatedAt());
        assertNotNull(user.getUpdatedAt());
    }

    private UserInSessionDTO setupSessionUserDTO() {
        return new UserInSessionDTO(
                "eac5b18d-4912-4216-ba61-8b2e379de594",
                "john.doe@example.com",
                "John",
                "Doe"
        );
    }
}