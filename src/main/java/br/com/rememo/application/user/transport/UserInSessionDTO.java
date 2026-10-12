package br.com.rememo.application.user.transport;

public record UserInSessionDTO(String identityProviderId,
                               String email,
                               String firstName,
                               String lastName) {
}
