package br.com.rememo.controller.response;

import java.time.LocalDateTime;

public record DeckDetailsResponse(String uuid,
                                  String name,
                                  String description,
                                  String icon,
                                  LocalDateTime createdAt,
                                  LocalDateTime updatedAt) {
}
