package br.com.rememo.application.transport;

public record SessionUserDTO(String identityProviderId,
                             String email,
                             String firstName,
                             String lastName) {
}
