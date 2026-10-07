package br.com.rememo.application;

import br.com.rememo.application.transport.SessionUserDTO;
import br.com.rememo.domain.User;
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
        SessionUserDTO sessionUserDTO = this.setupSessionUserDTO();

        when(this.userRepositoryPort.findByIdentityProviderId(sessionUserDTO.identityProviderId()))
                .thenReturn(Optional.empty());

        this.synchronizeUserService.synchronizeUser(sessionUserDTO);

        ArgumentCaptor<User> userArgumentCaptor = ArgumentCaptor.forClass(User.class);
        verify(this.userRepositoryPort).save(userArgumentCaptor.capture());
        User user = userArgumentCaptor.getValue();

        assertNotNull(user);
        assertNotNull(user.getUuid());
        assertEquals(sessionUserDTO.identityProviderId(), user.getIdentityProviderId());
        assertEquals(sessionUserDTO.firstName(), user.getFirstName());
        assertEquals(sessionUserDTO.lastName(), user.getLastName());
        assertEquals(sessionUserDTO.email(), user.getEmail());
        assertNotNull(user.getCreatedAt());
        assertNotNull(user.getUpdatedAt());
    }

    @Test
    @DisplayName("Should update a user that already exists")
    void shouldUpdateUserThatAlreadyExists() {
        SessionUserDTO sessionUserDTO = this.setupSessionUserDTO();

        User currentUser = User.create(
                "eac5b18d-4912-4216-ba61-8b2e379de594",
                "Jane",
                "Doe",
                "jane.doe@example.com"
        );

        when(this.userRepositoryPort.findByIdentityProviderId(sessionUserDTO.identityProviderId()))
                .thenReturn(Optional.of(currentUser));

        this.synchronizeUserService.synchronizeUser(sessionUserDTO);

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
        SessionUserDTO sessionUserDTO = this.setupSessionUserDTO();

        User currentUser = User.create(
                sessionUserDTO.identityProviderId(),
                sessionUserDTO.firstName(),
                sessionUserDTO.lastName(),
                sessionUserDTO.email()
        );

        when(this.userRepositoryPort.findByIdentityProviderId(sessionUserDTO.identityProviderId()))
                .thenReturn(Optional.of(currentUser));

        User user = this.synchronizeUserService.synchronizeUser(sessionUserDTO);

        assertNotNull(user);
        assertEquals(currentUser.getUuid(), user.getUuid());
        assertEquals(currentUser.getIdentityProviderId(), user.getIdentityProviderId());
        assertEquals(currentUser.getFirstName(), user.getFirstName());
        assertEquals(currentUser.getLastName(), user.getLastName());
        assertEquals(currentUser.getEmail(), user.getEmail());
        assertNotNull(user.getCreatedAt());
        assertNotNull(user.getUpdatedAt());
    }

    private SessionUserDTO setupSessionUserDTO() {
        return new SessionUserDTO(
                "eac5b18d-4912-4216-ba61-8b2e379de594",
                "john.doe@example.com",
                "John",
                "Doe"
        );
    }
}