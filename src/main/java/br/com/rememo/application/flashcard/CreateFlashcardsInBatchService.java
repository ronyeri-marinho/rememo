package br.com.rememo.application.flashcard;

import br.com.rememo.application.common.usecase.HtmlSanitizerUseCase;
import br.com.rememo.application.flashcard.transport.CreateFlashcardsInBatchDTO;
import br.com.rememo.application.flashcard.usecase.CreateFlashcardsInBatchUseCase;
import br.com.rememo.application.user.usecase.GetUserInSessionUseCase;
import br.com.rememo.domain.deck.Deck;
import br.com.rememo.domain.deck.exception.DeckNotFoundException;
import br.com.rememo.domain.flashcard.Flashcard;
import br.com.rememo.domain.user.User;
import br.com.rememo.persistence.deck.ports.DeckRepositoryPort;
import br.com.rememo.persistence.flashcard.ports.FlashcardRepositoryPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class CreateFlashcardsInBatchService implements CreateFlashcardsInBatchUseCase {
    private static final Logger LOGGER = LoggerFactory.getLogger(CreateFlashcardsInBatchService.class);
    private final GetUserInSessionUseCase getUserInSessionUseCase;
    private final HtmlSanitizerUseCase htmlSanitizerUseCase;
    private final DeckRepositoryPort deckRepositoryPort;
    private final FlashcardRepositoryPort flashcardRepositoryPort;

    public CreateFlashcardsInBatchService(GetUserInSessionUseCase getUserInSessionUseCase,
                                          HtmlSanitizerUseCase htmlSanitizerUseCase,
                                          DeckRepositoryPort deckRepositoryPort,
                                          FlashcardRepositoryPort flashcardRepositoryPort) {
        this.getUserInSessionUseCase = getUserInSessionUseCase;
        this.htmlSanitizerUseCase = htmlSanitizerUseCase;
        this.deckRepositoryPort = deckRepositoryPort;
        this.flashcardRepositoryPort = flashcardRepositoryPort;
    }

    @Override
    @Transactional
    public List<Flashcard> createInBatch(CreateFlashcardsInBatchDTO createFlashcardsInBatchDTO) {
        User userInSession = this.getUserInSessionUseCase.getUserInSession();

        Deck deck = this.deckRepositoryPort
                .findByUuidAndUserId(createFlashcardsInBatchDTO.deckId(), userInSession.getId())
                .orElseThrow(() -> new DeckNotFoundException(
                        createFlashcardsInBatchDTO.deckId(), userInSession.getUuid()
                ));

        List<Flashcard> flashcards = createFlashcardsInBatchDTO.flashcards()
                .stream()
                .map(createFlashcardDTO ->
                        Flashcard.create(
                                createFlashcardDTO.question(),
                                this.htmlSanitizerUseCase.sanitize(createFlashcardDTO.answer()),
                                deck
                        )).toList();

        LOGGER.debug(
                "Starting to save {} flashcards. deckId={}, userId={}",
                flashcards.size(),
                deck.getUuid(),
                userInSession.getUuid()
        );
        
        return this.flashcardRepositoryPort.saveAll(deck, flashcards);
    }
}
