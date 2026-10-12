package br.com.rememo.application.user;

import br.com.rememo.application.user.usecase.GetUserInSessionUseCase;
import br.com.rememo.domain.user.User;
import br.com.rememo.domain.user.exception.UnauthorizedException;
import br.com.rememo.domain.user.exception.UserNotFoundException;
import br.com.rememo.persistence.user.ports.UserRepositoryPort;
import org.jspecify.annotations.NonNull;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;

@Service
public class GetUserInSessionService implements GetUserInSessionUseCase {

    private final UserRepositoryPort userRepositoryPort;

    public GetUserInSessionService(UserRepositoryPort userRepositoryPort) {
        this.userRepositoryPort = userRepositoryPort;
    }

    @Override
    public User getUserInSession() throws UserNotFoundException {
        Authentication authentication = this.getAuthentication();

        Jwt jwt = this.getJwt(authentication);

        String identityProviderId = jwt.getSubject();

        if (identityProviderId == null || identityProviderId.isBlank()) {
            throw new UnauthorizedException("JWT subject is missing");
        }

        return this.userRepositoryPort.findByIdentityProviderId(identityProviderId)
                .orElseThrow(() -> new UserNotFoundException(identityProviderId));
    }

    private @NonNull Authentication getAuthentication() throws UnauthorizedException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            throw new UnauthorizedException("User is not authenticated");
        }

        return authentication;
    }

    private @NonNull Jwt getJwt(Authentication authentication) throws UnauthorizedException {
        Object principal = authentication.getPrincipal();
        if (!(principal instanceof Jwt jwt)) {
            throw new UnauthorizedException("Invalid authentication principal");
        }
        return jwt;
    }
}
