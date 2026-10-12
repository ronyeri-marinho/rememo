package br.com.rememo.application.user;

import br.com.rememo.domain.user.User;
import br.com.rememo.domain.user.exception.UnauthorizedException;
import br.com.rememo.persistence.user.ports.UserRepositoryPort;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class GetUserInSessionServiceTest {

    @Mock
    private UserRepositoryPort userRepositoryPort;

    @InjectMocks
    private GetUserInSessionService getUserInSessionService;

    @Test
    @DisplayName("Should return the current user in session")
    void shouldReturnTheCurrentUserInSession() {
        SecurityContext securityContext = mock(SecurityContext.class);
        Authentication authentication = mock(Authentication.class);
        Jwt jwt = mock(Jwt.class);
        User user = new User();
        user.setIdentityProviderId("2897ca4a-81ae-42b3-bdf6-69781639e4fd");

        try (MockedStatic<SecurityContextHolder> mockedSecurityContextHolder =
                     mockStatic(SecurityContextHolder.class)) {

            mockedSecurityContextHolder.when(SecurityContextHolder::getContext)
                    .thenReturn(securityContext);

            when(securityContext.getAuthentication()).thenReturn(authentication);
            when(authentication.isAuthenticated()).thenReturn(true);
            when(authentication.getPrincipal()).thenReturn(jwt);
            when(jwt.getSubject()).thenReturn(user.getIdentityProviderId());

            when(this.userRepositoryPort.findByIdentityProviderId(user.getIdentityProviderId()))
                    .thenReturn(Optional.of(user));

            User userInSession = this.getUserInSessionService.getUserInSession();

            assertNotNull(userInSession);
        }
    }

    @Test
    @DisplayName("Should throw exception when the identity provider id is null")
    void shouldThrowExceptionWhenIdentityProviderIdIsNull() {
        SecurityContext securityContext = mock(SecurityContext.class);
        Authentication authentication = mock(Authentication.class);
        Jwt jwt = mock(Jwt.class);

        try (MockedStatic<SecurityContextHolder> mockedSecurityContextHolder =
                     mockStatic(SecurityContextHolder.class)) {

            mockedSecurityContextHolder.when(SecurityContextHolder::getContext)
                    .thenReturn(securityContext);

            when(securityContext.getAuthentication()).thenReturn(authentication);
            when(authentication.isAuthenticated()).thenReturn(true);
            when(authentication.getPrincipal()).thenReturn(jwt);
            when(jwt.getSubject()).thenReturn(null);

            assertThrows(
                    UnauthorizedException.class,
                    () -> this.getUserInSessionService.getUserInSession(),
                    "JWT subject is missing"
            );
        }
    }

    @Test
    @DisplayName("Should throw exception when the identity provider id is blank")
    void shouldThrowExceptionWhenIdentityProviderIdIsBlank() {
        SecurityContext securityContext = mock(SecurityContext.class);
        Authentication authentication = mock(Authentication.class);
        Jwt jwt = mock(Jwt.class);

        try (MockedStatic<SecurityContextHolder> mockedSecurityContextHolder =
                     mockStatic(SecurityContextHolder.class)) {

            mockedSecurityContextHolder.when(SecurityContextHolder::getContext)
                    .thenReturn(securityContext);

            when(securityContext.getAuthentication()).thenReturn(authentication);
            when(authentication.isAuthenticated()).thenReturn(true);
            when(authentication.getPrincipal()).thenReturn(jwt);
            when(jwt.getSubject()).thenReturn("");

            assertThrows(
                    UnauthorizedException.class,
                    () -> this.getUserInSessionService.getUserInSession(),
                    "JWT subject is missing"
            );
        }
    }

    @Test
    @DisplayName("Should throw exception when the authentication is false")
    void shouldThrowExceptionWhenTheAuthenticationIsFalse() {
        SecurityContext securityContext = mock(SecurityContext.class);
        Authentication authentication = mock(Authentication.class);

        try (MockedStatic<SecurityContextHolder> mockedSecurityContextHolder =
                     mockStatic(SecurityContextHolder.class)) {

            mockedSecurityContextHolder.when(SecurityContextHolder::getContext)
                    .thenReturn(securityContext);

            when(securityContext.getAuthentication()).thenReturn(authentication);
            when(authentication.isAuthenticated()).thenReturn(false);

            assertThrows(
                    UnauthorizedException.class,
                    () -> this.getUserInSessionService.getUserInSession(),
                    "User is not authenticated"
            );
        }
    }

    @Test
    @DisplayName("Should throw exception when the authentication is null")
    void shouldThrowExceptionWhenTheAuthenticationIsNull() {
        SecurityContext securityContext = mock(SecurityContext.class);

        try (MockedStatic<SecurityContextHolder> mockedSecurityContextHolder =
                     mockStatic(SecurityContextHolder.class)) {

            mockedSecurityContextHolder.when(SecurityContextHolder::getContext)
                    .thenReturn(securityContext);

            when(securityContext.getAuthentication()).thenReturn(null);

            assertThrows(
                    UnauthorizedException.class,
                    () -> this.getUserInSessionService.getUserInSession(),
                    "User is not authenticated"
            );
        }
    }

    @Test
    @DisplayName("Should throw exception when the JWT is not valid")
    void shouldThrowExceptionWhenJwtIsNotValid() {
        SecurityContext securityContext = mock(SecurityContext.class);
        Authentication authentication = mock(Authentication.class);
        UsernamePasswordAuthenticationToken authenticationToken = mock(UsernamePasswordAuthenticationToken.class);

        try (MockedStatic<SecurityContextHolder> mockedSecurityContextHolder =
                     mockStatic(SecurityContextHolder.class)) {

            mockedSecurityContextHolder.when(SecurityContextHolder::getContext)
                    .thenReturn(securityContext);

            when(securityContext.getAuthentication()).thenReturn(authentication);
            when(authentication.isAuthenticated()).thenReturn(true);
            when(authentication.getPrincipal()).thenReturn(authenticationToken);

            assertThrows(
                    UnauthorizedException.class,
                    () -> this.getUserInSessionService.getUserInSession(),
                    "Invalid authentication principal"
            );
        }
    }
}