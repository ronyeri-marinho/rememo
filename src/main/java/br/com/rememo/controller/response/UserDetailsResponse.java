package br.com.rememo.controller.response;

import java.time.LocalDateTime;

public record UserDetailsResponse(String uuid,
                                  String firstName,
                                  String lastName,
                                  String email,
                                  LocalDateTime createdAt,
                                  LocalDateTime updatedAt) {
}
