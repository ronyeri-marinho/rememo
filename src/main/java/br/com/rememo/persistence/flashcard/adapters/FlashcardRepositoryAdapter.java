package br.com.rememo.persistence.flashcard.adapters;

import br.com.rememo.domain.deck.Deck;
import br.com.rememo.domain.deck.exception.DeckNotFoundException;
import br.com.rememo.domain.flashcard.Flashcard;
import br.com.rememo.persistence.deck.DeckEntity;
import br.com.rememo.persistence.deck.DeckRepository;
import br.com.rememo.persistence.flashcard.FlashcardEntity;
import br.com.rememo.persistence.flashcard.FlashcardRepository;
import br.com.rememo.persistence.flashcard.mappers.FlashcardPersistenceMapper;
import br.com.rememo.persistence.flashcard.ports.FlashcardRepositoryPort;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class FlashcardRepositoryAdapter implements FlashcardRepositoryPort {

    private final FlashcardRepository flashcardRepository;
    private final DeckRepository deckRepository;

    public FlashcardRepositoryAdapter(FlashcardRepository flashcardRepository,
                                      DeckRepository deckRepository) {
        this.flashcardRepository = flashcardRepository;
        this.deckRepository = deckRepository;
    }

    @Override
    public List<Flashcard> saveAll(Deck deck, List<Flashcard> flashcards) {
        DeckEntity deckEntity = this.deckRepository.findByUuidAndUserId(deck.getUuid(), deck.getUser().getId())
                .orElseThrow(() -> new DeckNotFoundException(deck.getUuid()));

        List<FlashcardEntity> entities = flashcards
                .stream()
                .map(flashcard -> FlashcardPersistenceMapper.toEntity(flashcard, deckEntity))
                .toList();

        return this.flashcardRepository
                .saveAll(entities).stream().map(FlashcardPersistenceMapper::toDomain).toList();
    }
}
