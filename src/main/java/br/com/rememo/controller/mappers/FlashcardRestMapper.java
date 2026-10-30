package br.com.rememo.controller.mappers;

import br.com.rememo.application.flashcard.transport.CreateFlashcardDTO;
import br.com.rememo.application.flashcard.transport.CreateFlashcardsInBatchDTO;
import br.com.rememo.controller.request.CreateFlashcardRequest;
import br.com.rememo.controller.request.CreateFlashcardsInBatchRequest;
import br.com.rememo.controller.response.FlashcardDetailsResponse;
import br.com.rememo.domain.flashcard.Flashcard;

import java.util.UUID;

public class FlashcardRestMapper {
    private FlashcardRestMapper() {

    }

    public static FlashcardDetailsResponse toDetails(Flashcard flashcard) {
        return new FlashcardDetailsResponse(
                flashcard.getUuid().toString(),
                flashcard.getQuestion(),
                flashcard.getAnswer(),
                flashcard.getCreatedAt(),
                flashcard.getUpdatedAt()
        );
    }

    public static CreateFlashcardsInBatchDTO toCreateFlashcardsInBatchDTO(UUID deckId,
                                                                          CreateFlashcardsInBatchRequest request) {
        return new CreateFlashcardsInBatchDTO(
                deckId,
                request.flashcards().stream().map(FlashcardRestMapper::toCreateFlashcardDTO).toList()
        );
    }

    public static CreateFlashcardDTO toCreateFlashcardDTO(CreateFlashcardRequest request) {
        return new CreateFlashcardDTO(
                request.question(),
                request.answer()
        );
    }
}
