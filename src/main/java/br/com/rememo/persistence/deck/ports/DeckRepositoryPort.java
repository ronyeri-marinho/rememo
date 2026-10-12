package br.com.rememo.persistence.deck.ports;

import br.com.rememo.domain.deck.Deck;

public interface DeckRepositoryPort {

    Deck save(Deck deck);
}
