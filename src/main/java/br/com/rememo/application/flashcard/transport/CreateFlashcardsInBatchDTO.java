package br.com.rememo.application.flashcard.transport;

import java.util.List;
import java.util.UUID;

public record CreateFlashcardsInBatchDTO(UUID deckId,
                                         List<CreateFlashcardDTO> flashcards) {
}
