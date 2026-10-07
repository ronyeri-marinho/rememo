package br.com.rememo.controller;

import br.com.rememo.controller.mappers.UserRestMapper;
import br.com.rememo.controller.response.UserDetailsResponse;
import br.com.rememo.application.usecase.SynchronizeUserUseCase;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.UriComponentsBuilder;

@RestController
@RequestMapping("/users")
public class UserController {

    private final SynchronizeUserUseCase synchronizeUserUseCase;

    public UserController(SynchronizeUserUseCase synchronizeUserUseCase) {
        this.synchronizeUserUseCase = synchronizeUserUseCase;
    }

    @PostMapping("/sync")
    public ResponseEntity<UserDetailsResponse> synchronizeUser(@AuthenticationPrincipal Jwt jwt,
                                                               UriComponentsBuilder uriComponentsBuilder) {
        UserDetailsResponse response = UserRestMapper
                .toDetails(this.synchronizeUserUseCase.synchronizeUser(UserRestMapper.toSessionUser(jwt)));

        return ResponseEntity.created(uriComponentsBuilder
                        .path("/users/{uuid}")
                        .buildAndExpand(response.uuid())
                        .toUri())
                .body(response);
    }
}
