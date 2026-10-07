package br.com.rememo.controller.mappers;

import br.com.rememo.controller.response.UserDetailsResponse;
import br.com.rememo.domain.User;
import br.com.rememo.application.transport.SessionUserDTO;
import org.springframework.security.oauth2.jwt.Jwt;

public class UserRestMapper {
    private UserRestMapper() {

    }

    public static SessionUserDTO toSessionUser(Jwt jwt) {
        return new SessionUserDTO(
                jwt.getClaimAsString("sub"),
                jwt.getClaimAsString("email"),
                jwt.getClaimAsString("given_name"),
                jwt.getClaimAsString("family_name")
        );
    }

    public static UserDetailsResponse toDetails(User user) {
        return new UserDetailsResponse(
                user.getUuid().toString(),
                user.getFirstName(),
                user.getLastName(),
                user.getEmail(),
                user.getCreatedAt(),
                user.getUpdatedAt()
        );
    }
}
