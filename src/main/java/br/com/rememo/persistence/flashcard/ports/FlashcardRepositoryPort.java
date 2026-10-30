package br.com.rememo.persistence.flashcard.ports;

import br.com.rememo.domain.deck.Deck;
import br.com.rememo.domain.flashcard.Flashcard;

import java.util.List;

public interface FlashcardRepositoryPort {

    List<Flashcard> saveAll(Deck deck, List<Flashcard> flashcards);
}
