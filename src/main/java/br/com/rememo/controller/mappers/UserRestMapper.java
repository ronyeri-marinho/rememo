package br.com.rememo.controller.mappers;

import br.com.rememo.application.user.transport.UserInSessionDTO;
import br.com.rememo.controller.response.UserDetailsResponse;
import br.com.rememo.domain.user.User;
import org.springframework.security.oauth2.jwt.Jwt;

public class UserRestMapper {
    private UserRestMapper() {

    }

    public static UserInSessionDTO toUserInSession(Jwt jwt) {
        return new UserInSessionDTO(
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
