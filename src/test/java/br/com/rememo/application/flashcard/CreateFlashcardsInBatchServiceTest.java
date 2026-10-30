package br.com.rememo.application.flashcard;

import br.com.rememo.application.common.usecase.HtmlSanitizerUseCase;
import br.com.rememo.application.flashcard.transport.CreateFlashcardDTO;
import br.com.rememo.application.flashcard.transport.CreateFlashcardsInBatchDTO;
import br.com.rememo.application.user.usecase.GetUserInSessionUseCase;
import br.com.rememo.domain.deck.Deck;
import br.com.rememo.domain.deck.exception.DeckNotFoundException;
import br.com.rememo.domain.flashcard.Flashcard;
import br.com.rememo.domain.user.User;
import br.com.rememo.persistence.deck.ports.DeckRepositoryPort;
import br.com.rememo.persistence.flashcard.ports.FlashcardRepositoryPort;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CreateFlashcardsInBatchServiceTest {

    @Captor
    private ArgumentCaptor<List<Flashcard>> flashcardsArgumentCaptor;

    @Mock
    private GetUserInSessionUseCase getUserInSessionUseCase;

    @Mock
    private HtmlSanitizerUseCase htmlSanitizerUseCase;

    @Mock
    private DeckRepositoryPort deckRepositoryPort;

    @Mock
    private FlashcardRepositoryPort flashcardRepositoryPort;

    @InjectMocks
    private CreateFlashcardsInBatchService createFlashcardsInBatchService;

    @Test
    @DisplayName("Should throw exception when deck is not found")
    void shouldThrowExceptionWhenDeckIsNotFound() {
        User user = setupUser();
        CreateFlashcardsInBatchDTO createFlashcardsInBatchDTO =
                this.setupCreateFlashcardsInBatchDTO(this.setupCreateFlashcardDTO());

        when(this.getUserInSessionUseCase.getUserInSession())
                .thenReturn(user);

        when(this.deckRepositoryPort.findByUuidAndUserId(createFlashcardsInBatchDTO.deckId(), user.getId()))
                .thenReturn(Optional.empty());

        assertThrows(
                DeckNotFoundException.class,
                () -> this.createFlashcardsInBatchService.createInBatch(createFlashcardsInBatchDTO)
        );
    }

    @Test
    @DisplayName("Should save all flashcards into deck")
    void shouldSaveAllFlashcardsIntoDeck() {
        User user = setupUser();
        Deck deck = mock(Deck.class);
        CreateFlashcardDTO createFlashcardDTO = this.setupCreateFlashcardDTO();
        CreateFlashcardsInBatchDTO createFlashcardsInBatchDTO = this.setupCreateFlashcardsInBatchDTO(createFlashcardDTO);

        when(this.getUserInSessionUseCase.getUserInSession())
                .thenReturn(user);

        when(this.deckRepositoryPort.findByUuidAndUserId(createFlashcardsInBatchDTO.deckId(), user.getId()))
                .thenReturn(Optional.of(deck));

        when(this.htmlSanitizerUseCase.sanitize(createFlashcardDTO.answer()))
                .thenReturn(createFlashcardDTO.answer());

        this.createFlashcardsInBatchService.createInBatch(createFlashcardsInBatchDTO);

        verify(this.flashcardRepositoryPort).saveAll(eq(deck), this.flashcardsArgumentCaptor.capture());
        List<Flashcard> flashcards = this.flashcardsArgumentCaptor.getValue();

        assertEquals(1, flashcards.size());
        Flashcard flashcard = flashcards.stream().findFirst().stream().findFirst().orElseThrow(AssertionError::new);

        assertNotNull(flashcard.getUuid());
        assertEquals(createFlashcardDTO.question(), flashcard.getQuestion());
        assertEquals(createFlashcardDTO.answer(), flashcard.getAnswer());
        assertNotNull(flashcard.getCreatedAt());
        assertNotNull(flashcard.getUpdatedAt());
    }

    private User setupUser() {
        User user = new User();
        user.setId(1L);
        return user;
    }

    private CreateFlashcardsInBatchDTO setupCreateFlashcardsInBatchDTO(CreateFlashcardDTO createFlashcardDTO) {
        return new CreateFlashcardsInBatchDTO(
                UUID.randomUUID(),
                List.of(createFlashcardDTO)
        );
    }

    private CreateFlashcardDTO setupCreateFlashcardDTO() {
        return new CreateFlashcardDTO(
                "How do Java developers like their coffee?",
                "Imported and strongly typed"
        );
    }
}