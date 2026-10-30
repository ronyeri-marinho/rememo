package br.com.rememo.persistence.flashcard.mappers;

import br.com.rememo.domain.flashcard.Flashcard;
import br.com.rememo.persistence.deck.DeckEntity;
import br.com.rememo.persistence.deck.mappers.DeckPersistenceMapper;
import br.com.rememo.persistence.flashcard.FlashcardEntity;

public class FlashcardPersistenceMapper {
    private FlashcardPersistenceMapper() {

    }

    public static Flashcard toDomain(FlashcardEntity flashcardEntity) {
        Flashcard flashcard = new Flashcard();
        flashcard.setId(flashcardEntity.getId());
        flashcard.setUuid(flashcardEntity.getUuid());
        flashcard.setQuestion(flashcardEntity.getQuestion());
        flashcard.setAnswer(flashcardEntity.getAnswer());
        flashcard.setDeck(DeckPersistenceMapper.toDomain(flashcardEntity.getDeck()));
        flashcard.setCreatedAt(flashcardEntity.getCreatedAt());
        flashcard.setUpdatedAt(flashcardEntity.getUpdatedAt());
        return flashcard;
    }

    public static FlashcardEntity toEntity(Flashcard flashcard, DeckEntity deckEntity) {
        FlashcardEntity flashcardEntity = new FlashcardEntity();
        flashcardEntity.setId(flashcard.getId());
        flashcardEntity.setUuid(flashcard.getUuid());
        flashcardEntity.setQuestion(flashcard.getQuestion());
        flashcardEntity.setAnswer(flashcard.getAnswer());
        flashcardEntity.setDeck(deckEntity);
        flashcardEntity.setCreatedAt(flashcard.getCreatedAt());
        flashcardEntity.setUpdatedAt(flashcard.getUpdatedAt());
        return flashcardEntity;
    }
}
