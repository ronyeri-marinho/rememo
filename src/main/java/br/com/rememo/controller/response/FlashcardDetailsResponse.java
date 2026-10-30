package br.com.rememo.controller.response;

import java.time.LocalDateTime;

public record FlashcardDetailsResponse(String uuid,
                                       String question,
                                       String answer,
                                       LocalDateTime createdAt,
                                       LocalDateTime updatedAt) {
}
